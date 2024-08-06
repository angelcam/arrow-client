// Copyright 2017 click2stream, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::io;

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::BytesMut;

use futures::task::{Context, Poll, Waker};
use futures::{Future, Stream};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::io::{poll_read_buf, poll_write_buf};

use crate::context::ApplicationContext;
use crate::net::arrow::connector::ServiceConnector;
use crate::net::arrow::error::{ArrowError, ConnectionError};
use crate::net::arrow::proto::msg::control::{
    ControlMessage, ControlMessageFactory, EC_CONNECTION_ERROR, EC_NO_ERROR,
};
use crate::net::arrow::proto::msg::ArrowMessage;
use crate::net::raw::ether::MacAddr;
use crate::svc_table::{BoxServiceTable, ServiceTable, ServiceType};
use crate::utils::logger::{BoxLogger, Logger};

const BUFFER_CAPACITY: usize = 8192;

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(20);

/// Session context.
struct SessionContext {
    cmsg_factory: ControlMessageFactory,
    service_id: u16,
    session_id: u32,
    input: BytesMut,
    output: BytesMut,
    input_capacity: usize,
    output_capacity: usize,
    output_written: usize,
    session_manager_task: Option<Waker>,
    session_transport_task: Option<Waker>,
    closed: bool,
    error: Option<ConnectionError>,
}

impl SessionContext {
    /// Create a new session context for a given service ID and session ID.
    fn new(
        cmsg_factory: ControlMessageFactory,
        service_id: u16,
        session_id: u32,
        window_size: usize,
    ) -> Self {
        Self {
            cmsg_factory,
            service_id,
            session_id,
            input: BytesMut::with_capacity(BUFFER_CAPACITY),
            output: BytesMut::with_capacity(BUFFER_CAPACITY),
            input_capacity: window_size,
            output_capacity: window_size,
            output_written: 0,
            session_manager_task: None,
            session_transport_task: None,
            closed: false,
            error: None,
        }
    }

    /// Process data acknowledge.
    fn process_data_ack(&mut self, length: usize) {
        self.input_capacity += length;

        // we MUST notify the session manager task that the input is available
        // again
        if let Some(task) = self.session_manager_task.take() {
            task.wake();
        }
    }

    /// Return a DATA_ACK message if we managed to write any data to the
    /// output.
    fn take_data_ack(&mut self) -> Option<ControlMessage> {
        if self.output_written > 0 {
            let len = std::mem::replace(&mut self.output_written, 0);

            self.output_capacity += len;

            let msg = self.cmsg_factory.data_ack(self.session_id, len as u32);

            Some(msg)
        } else {
            None
        }
    }

    /// Extend the output buffer with data from a given Arrow Message.
    fn push_output_message(&mut self, msg: ArrowMessage) {
        // ignore all incoming messages after the connection gets closed
        if self.closed {
            return;
        }

        let data = msg.payload();

        if data.len() > self.output_capacity {
            // the Arrow Service exceeded the session capacity
            self.set_error(ConnectionError::new("session capacity exceeded"));
        } else {
            self.output_capacity -= data.len();

            self.output.extend_from_slice(data);

            // we MUST notify the transport task that there is some data
            // available in the output buffer again
            if !self.output.is_empty() {
                if let Some(task) = self.session_transport_task.take() {
                    task.wake();
                }
            }
        }
    }

    /// Take the next Arrow Message to be sent to the Arrow Service.
    ///
    /// The method returns:
    /// * `Poll::Ready(Some(Ok(_)))` if there was a message available
    /// * `Poll::Ready(None)` if there was no message available and the context
    ///   has been closed
    /// * `Poll::Pending` if there was no message available
    fn take_arrow_message(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Option<Result<ArrowMessage, ConnectionError>>> {
        if let Some(msg) = self.take_data_ack() {
            return Poll::Ready(Some(Ok(msg.into())));
        }

        let take = self.input_capacity.min(self.input.len());

        self.input_capacity -= take;

        let data = self.input.split_to(take);

        // we MUST notify the transport task that the input buffer is writeable
        // again
        if self.input.len() < BUFFER_CAPACITY {
            if let Some(task) = self.session_transport_task.take() {
                task.wake();
            }
        }

        if !data.is_empty() {
            Poll::Ready(Some(Ok(ArrowMessage::new(
                self.service_id,
                self.session_id,
                data.freeze(),
            ))))
        } else if self.closed {
            match self.error.take() {
                Some(err) => Poll::Ready(Some(Err(err))),
                None => Poll::Ready(None),
            }
        } else {
            let task = cx.waker();

            // save the current task and wait until there is some data
            // available in the input buffer again (or until we receive a
            // DATA_ACK message)
            self.session_manager_task = Some(task.clone());

            Poll::Pending
        }
    }

    /// Read more data into the input buffer.
    fn poll_read_input_buf<S>(
        &mut self,
        cx: &mut Context,
        stream: &mut S,
    ) -> Poll<io::Result<usize>>
    where
        S: AsyncRead + Unpin,
    {
        let current_capacity = self.input.capacity();

        // make sure that the input buffer can always contain at least
        // `BUFFER_CAPACITY` bytes
        if current_capacity < BUFFER_CAPACITY {
            self.input.reserve(BUFFER_CAPACITY - current_capacity);
        }

        poll_read_buf(Pin::new(stream), cx, &mut self.input)
    }

    /// Write data from the output buffer.
    fn poll_write_output_buf<S>(
        &mut self,
        cx: &mut Context<'_>,
        stream: &mut S,
    ) -> Poll<io::Result<usize>>
    where
        S: AsyncWrite + Unpin,
    {
        poll_write_buf(Pin::new(stream), cx, &mut self.output)
    }

    /// Try to read data from a given `AsyncRead` stream into the input buffer.
    fn poll_read_input<S>(&mut self, cx: &mut Context, stream: &mut S) -> Poll<()>
    where
        S: AsyncRead + Unpin,
    {
        let input_buffer_len = self.input.len();

        if self.closed {
            Poll::Ready(())
        } else if input_buffer_len >= BUFFER_CAPACITY {
            let task = cx.waker();

            // save the current task and wait until there is some space in
            // the input buffer again
            self.session_transport_task = Some(task.clone());

            Poll::Pending
        } else if let Poll::Ready(res) = self.poll_read_input_buf(cx, stream) {
            match res {
                Ok(0) => self.close(),
                Err(err) => self.set_error(ConnectionError::from(err)),
                _ => (),
            }

            // we MUST notify the session manager task that there is more data
            // in the input buffer
            if !self.input.is_empty() {
                if let Some(task) = self.session_manager_task.take() {
                    task.wake();
                }
            }

            Poll::Ready(())
        } else {
            let task = cx.waker();

            // save the current task and wait until the stream is ready again
            self.session_transport_task = Some(task.clone());

            Poll::Pending
        }
    }

    /// Try to write data from the output buffer into a given `AsyncWrite`
    /// stream.
    fn poll_write_output<S>(&mut self, cx: &mut Context, stream: &mut S) -> Poll<()>
    where
        S: AsyncWrite + Unpin,
    {
        if self.output.is_empty() {
            if self.closed {
                Poll::Ready(())
            } else {
                let task = cx.waker();

                // save the current task and wait until there is some data in
                // the output buffer available again
                self.session_transport_task = Some(task.clone());

                Poll::Pending
            }
        } else if let Poll::Ready(res) = self.poll_write_output_buf(cx, stream) {
            match res {
                Ok(len) => {
                    self.output_written += len;

                    // we MUST notify the session manager task that there is a
                    // DATA_ACK message to be sent
                    if let Some(task) = self.session_manager_task.take() {
                        task.wake();
                    }
                }
                Err(err) => self.set_error(ConnectionError::from(err)),
            }

            Poll::Ready(())
        } else {
            let task = cx.waker();

            // save the current task and wait until the stream is ready again
            self.session_transport_task = Some(task.clone());

            Poll::Pending
        }
    }

    /// Mark the context as closed. Note that this method does not flush any
    /// buffer.
    fn close(&mut self) {
        self.closed = true;

        // we MUST notify the session transport task that the session has been
        // closed
        if let Some(task) = self.session_transport_task.take() {
            task.wake();
        }

        // we MUST notify the session manager task that the session has been
        // closed
        if let Some(task) = self.session_manager_task.take() {
            task.wake();
        }
    }

    /// Mark the context as closed and set a given error. Note that this
    /// method does not flush any buffer.
    fn set_error(&mut self, err: ConnectionError) {
        // ignore all errors after the connection gets closed
        if self.closed {
            return;
        }

        self.error = Some(err);

        self.close();
    }
}

/// Arrow session (i.e. connection to an external service).
struct Session {
    context: Arc<Mutex<SessionContext>>,
}

impl Session {
    /// Create a new session for a given service ID and session ID.
    #[allow(clippy::too_many_arguments)]
    fn new<C, S>(
        cmsg_factory: ControlMessageFactory,
        svc_connector: C,
        service_id: u16,
        session_id: u32,
        svc_type: ServiceType,
        mac: MacAddr,
        addr: SocketAddr,
        window_size: usize,
    ) -> Self
    where
        C: ServiceConnector<Connection = S> + 'static,
        S: AsyncRead + AsyncWrite + Send + Unpin,
    {
        let context = Arc::new(Mutex::new(SessionContext::new(
            cmsg_factory,
            service_id,
            session_id,
            window_size,
        )));

        let session = Session {
            context: context.clone(),
        };

        tokio::spawn(async move {
            let transport =
                SessionTransport::connect(context.clone(), svc_connector, svc_type, mac, addr);

            match transport.await {
                Ok(transport) => transport.await,
                Err(err) => context.lock().unwrap().set_error(err),
            }
        });

        session
    }

    /// Process data acknowledge.
    fn process_data_ack(&mut self, length: usize) {
        self.context.lock().unwrap().process_data_ack(length)
    }

    /// Push a given Arrow Message into the output buffer.
    fn push(&mut self, msg: ArrowMessage) {
        self.context.lock().unwrap().push_output_message(msg)
    }

    /// Take the next Arrow Message to be sent to the Arrow Service.
    ///
    /// The method returns:
    /// * `Poll::Ready(Some(Ok(_)))` if there was a message available
    /// * `Poll::Ready(None)` if there was no message available and the context
    ///   has been closed
    /// * `Poll::Pending` if there was no message available
    fn take(&mut self, cx: &mut Context) -> Poll<Option<Result<ArrowMessage, ConnectionError>>> {
        self.context.lock().unwrap().take_arrow_message(cx)
    }

    /// Mark the session as closed. The session context won't accept any new
    /// data, however the buffered data can be still processed. It's up to
    /// the corresponding tasks to consume all remaining data.
    fn close(&mut self) {
        self.context.lock().unwrap().close()
    }
}

/// Session transport. It is a future that drives communication with the remote
/// host.
struct SessionTransport<S> {
    context: Arc<Mutex<SessionContext>>,
    stream: S,
}

impl<S> SessionTransport<S> {
    /// Create a new session transport by connecting to a given host.
    async fn connect<C>(
        context: Arc<Mutex<SessionContext>>,
        svc_connector: C,
        svc_type: ServiceType,
        mac: MacAddr,
        addr: SocketAddr,
    ) -> Result<Self, ConnectionError>
    where
        C: ServiceConnector<Connection = S>,
        S: Unpin,
    {
        let connect = svc_connector.connect(svc_type, mac, addr);

        let stream = tokio::time::timeout(CONNECTION_TIMEOUT, connect)
            .await
            .map_err(|_| ConnectionError::new("connection timeout"))?
            .map_err(ConnectionError::from)?;

        let transport = Self { context, stream };

        Ok(transport)
    }
}

impl<S> Future for SessionTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // just to make the borrow checker happy
        let ctx = self.context.clone();

        let mut context = ctx.lock().unwrap();

        if context.closed {
            return Poll::Ready(());
        }

        let read_poll = context.poll_read_input(cx, &mut self.stream);
        let write_poll = context.poll_write_output(cx, &mut self.stream);

        // poll us again ASAP if there is more work to be done
        if read_poll.is_ready() || write_poll.is_ready() {
            cx.waker().wake_by_ref();
        }

        Poll::Pending
    }
}

/// Arrow session manager.
pub struct SessionManager<C> {
    logger: BoxLogger,
    window_size: usize,
    gateway_mode: bool,
    svc_table: BoxServiceTable,
    cmsg_factory: ControlMessageFactory,
    cmsg_queue: VecDeque<ArrowMessage>,
    svc_connector: C,
    sessions: HashMap<u32, Session>,
    poll_order: VecDeque<u32>,
    task: Option<Waker>,
}

impl<C> SessionManager<C>
where
    C: ServiceConnector + Clone + 'static,
    C::Connection: Send + Unpin,
{
    /// Create a new session manager.
    pub fn new(
        app_context: ApplicationContext,
        cmsg_factory: ControlMessageFactory,
        svc_connector: C,
        window_size: usize,
        gateway_mode: bool,
    ) -> Self {
        let svc_table = app_context.get_service_table();

        Self {
            logger: app_context.get_logger(),
            window_size,
            gateway_mode,
            svc_table: svc_table.boxed(),
            cmsg_factory,
            cmsg_queue: VecDeque::new(),
            svc_connector,
            sessions: HashMap::new(),
            poll_order: VecDeque::new(),
            task: None,
        }
    }

    /// Get number of active sessions.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Create a new session.
    pub fn connect(&mut self, service_id: u16, session_id: u32) {
        match self.connect_inner(service_id, session_id) {
            Ok(session) => {
                self.poll_order.push_back(session_id);
                self.sessions.insert(session_id, session);
            }
            Err(err) => {
                log_warn!(
                    self.logger,
                    "unable to connect to a remote service: {}",
                    err
                );

                let msg = self.create_hup_message(session_id, EC_CONNECTION_ERROR);

                self.cmsg_queue.push_back(msg);
            }
        }

        // notify the message consuming task
        if let Some(task) = self.task.take() {
            task.wake();
        }
    }

    /// Send a given Arrow Message to the corresponding service using a given
    /// session (as specified by the message).
    pub fn send(&mut self, msg: ArrowMessage) {
        let header = msg.header();

        let session_id = header.session;

        if let Some(session) = self.sessions.get_mut(&session_id) {
            session.push(msg);
        } else {
            let msg = self.create_hup_message(header.session, EC_CONNECTION_ERROR);

            self.cmsg_queue.push_back(msg);

            // notify the message consuming task
            if let Some(task) = self.task.take() {
                task.wake();
            }
        }
    }

    /// Close a given session.
    pub fn close(&mut self, session_id: u32, _: u32) {
        if let Some(mut session) = self.sessions.remove(&session_id) {
            log_info!(
                self.logger,
                "closing service connection; session ID: {:06x}",
                session_id
            );

            session.close();
        }
    }

    /// Process data acknowledge.
    pub fn process_data_ack(&mut self, session_id: u32, length: u32) {
        if let Some(session) = self.sessions.get_mut(&session_id) {
            session.process_data_ack(length as usize);
        }
    }

    /// Connect to a given service and create an associated session object
    /// with a given ID.
    fn connect_inner(&mut self, service_id: u16, session_id: u32) -> Result<Session, ArrowError> {
        if self.sessions.contains_key(&session_id) {
            return Err(ArrowError::other(format!(
                "the session already exists; session ID: {:06x}",
                session_id
            )));
        }

        let svc = self
            .svc_table
            .get(service_id)
            .ok_or_else(|| ArrowError::other(format!("unknown service ID: {:04x}", service_id)))?;

        let mac = svc.mac().unwrap_or_else(MacAddr::zero);

        let addr = svc.address().ok_or_else(|| {
            ArrowError::other(format!(
                "there is no address for a given service; service ID: {:04x}",
                service_id
            ))
        })?;

        let ip = addr.ip();

        if !self.gateway_mode && !ip.is_loopback() {
            return Err(ArrowError::other(format!(
                "gateway mode disabled (service ID: {:04x})",
                service_id
            )));
        }

        log_info!(
            self.logger,
            "connecting to remote service: {}, service ID: {:04x}, session ID: {:06x}",
            addr,
            service_id,
            session_id
        );

        Ok(Session::new(
            self.cmsg_factory.clone(),
            self.svc_connector.clone(),
            service_id,
            session_id,
            svc.service_type(),
            mac,
            addr,
            self.window_size,
        ))
    }

    /// Create HUP message for a given session.
    fn create_hup_message(&mut self, session_id: u32, error_code: u32) -> ArrowMessage {
        log_debug!(
            self.logger,
            "sending a HUP message (session ID: {:06x}, error_code: {:08x})...",
            session_id,
            error_code
        );

        ArrowMessage::from(self.cmsg_factory.hup(session_id, error_code))
    }
}

impl<C> Drop for SessionManager<C> {
    fn drop(&mut self) {
        for (session_id, mut session) in self.sessions.drain() {
            log_info!(
                self.logger,
                "closing service connection; session ID: {:06x}",
                session_id
            );

            session.close();
        }
    }
}

impl<C> Stream for SessionManager<C>
where
    C: ServiceConnector + Clone + Unpin + 'static,
    C::Connection: Send + Unpin,
{
    type Item = Result<ArrowMessage, ArrowError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        if let Some(msg) = self.cmsg_queue.pop_front() {
            return Poll::Ready(Some(Ok(msg)));
        }

        for _ in 0..self.poll_order.len() {
            if let Some(session_id) = self.poll_order.pop_front() {
                if let Some(mut session) = self.sessions.remove(&session_id) {
                    match session.take(cx) {
                        Poll::Pending => {
                            self.sessions.insert(session_id, session);
                            self.poll_order.push_back(session_id);
                        }
                        Poll::Ready(None) => {
                            log_info!(
                                self.logger,
                                "service connection closed; session ID: {:06x}",
                                session_id
                            );

                            let msg = self.create_hup_message(session_id, EC_NO_ERROR);

                            return Poll::Ready(Some(Ok(msg)));
                        }
                        Poll::Ready(Some(Ok(msg))) => {
                            self.sessions.insert(session_id, session);
                            self.poll_order.push_back(session_id);

                            return Poll::Ready(Some(Ok(msg)));
                        }
                        Poll::Ready(Some(Err(err))) => {
                            log_warn!(
                                self.logger,
                                "service connection error; session ID: {:06x}: {}",
                                session_id,
                                err
                            );

                            let msg = self.create_hup_message(session_id, EC_CONNECTION_ERROR);

                            return Poll::Ready(Some(Ok(msg)));
                        }
                    }
                }
            }
        }

        let task = cx.waker();

        // the session manager needs to be re-polled in case there is a new
        // session or control message
        self.task = Some(task.clone());

        Poll::Pending
    }
}
