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

use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::BytesMut;

use futures::task::{Context, Poll, Waker};
use futures::{Future, Stream};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::context::ApplicationContext;
use crate::net::arrow::error::{ArrowError, ConnectionError};
use crate::net::arrow::proto::msg::control::{
    ControlMessageFactory, EC_CONNECTION_ERROR, EC_NO_ERROR,
};
use crate::net::arrow::proto::msg::ArrowMessage;
use crate::svc_table::{BoxServiceTable, ServiceTable};
use crate::utils::logger::{BoxLogger, Logger};

const OUTPUT_BUFFER_LIMIT: usize = 4 * 1024 * 1024;

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(20);

/// Session context.
struct SessionContext {
    service_id: u16,
    session_id: u32,
    input: BytesMut,
    output: BytesMut,
    session_manager_task: Option<Waker>,
    session_transport_task: Option<Waker>,
    closed: bool,
    error: Option<ConnectionError>,
}

impl SessionContext {
    /// Create a new session context for a given service ID and session ID.
    fn new(service_id: u16, session_id: u32) -> Self {
        Self {
            service_id,
            session_id,
            input: BytesMut::with_capacity(8192),
            output: BytesMut::with_capacity(8192),
            session_manager_task: None,
            session_transport_task: None,
            closed: false,
            error: None,
        }
    }

    /// Extend the output buffer with data from a given Arrow Message.
    fn push_output_message(&mut self, msg: ArrowMessage) {
        // ignore all incoming messages after the connection gets closed
        if self.closed {
            return;
        }

        let data = msg.payload();

        if (self.output.len() + data.len()) > OUTPUT_BUFFER_LIMIT {
            // we cannot backpressure here, so we'll set an error state
            self.set_error(ConnectionError::from("output buffer limit exceeded"));
        } else {
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

    /// Take all the data from the input buffer and return them as an Arrow
    /// Message. The method returns:
    /// * `Poll::Ready(Some(Ok(_)))` if there was some data available
    /// * `Poll::Ready(None)` if there was no data available and the context
    ///   has been closed
    /// * `Poll::Pending` if there was no data available
    fn take_input_message(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Option<Result<ArrowMessage, ConnectionError>>> {
        let data = self.input.split().freeze();

        // we MUST notify the transport task that the input buffer is empty
        // again
        if let Some(task) = self.session_transport_task.take() {
            task.wake();
        }

        if !data.is_empty() {
            let message = ArrowMessage::new(self.service_id, self.session_id, data);

            Poll::Ready(Some(Ok(message)))
        } else if self.closed {
            match self.error.take() {
                Some(err) => Poll::Ready(Some(Err(err))),
                None => Poll::Ready(None),
            }
        } else {
            // save the current task and wait until there is some data
            // available in the input buffer again
            self.session_manager_task = Some(cx.waker().clone());

            Poll::Pending
        }
    }

    /// Try to read data from a given `AsyncRead` stream into the input buffer.
    fn poll_read_input<S>(&mut self, cx: &mut Context, stream: &mut S) -> Poll<()>
    where
        S: AsyncRead + Unpin,
    {
        let input_buffer_len = self.input.len();
        let input_buffer_capacity = self.input.capacity();

        let stream = Pin::new(stream);

        if self.closed {
            Poll::Ready(())
        } else if input_buffer_len >= input_buffer_capacity {
            // save the current task and wait until there is some space in
            // the input buffer again
            self.session_transport_task = Some(cx.waker().clone());

            Poll::Pending
        } else if let Poll::Ready(res) = stream.poll_read_buf(cx, &mut self.input) {
            match res {
                Ok(len) if len == 0 => self.close(),
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
            // save the current task and wait until the stream is ready again
            self.session_transport_task = Some(cx.waker().clone());

            Poll::Pending
        }
    }

    /// Try to write data from the output buffer into a given `AsyncWrite`
    /// stream.
    fn poll_write_output<S>(&mut self, cx: &mut Context, stream: &mut S) -> Poll<()>
    where
        S: AsyncWrite + Unpin,
    {
        let stream = Pin::new(stream);

        if self.output.is_empty() {
            if self.closed {
                Poll::Ready(())
            } else {
                // save the current task and wait until there is some data in
                // the output buffer available again
                self.session_transport_task = Some(cx.waker().clone());

                Poll::Pending
            }
        } else if let Poll::Ready(res) = stream.poll_write_buf(cx, &mut self.output) {
            if let Err(err) = res {
                self.set_error(ConnectionError::from(err));
            }

            Poll::Ready(())
        } else {
            // save the current task and wait until the stream is ready again
            self.session_transport_task = Some(cx.waker().clone());

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
    fn new(service_id: u16, session_id: u32, addr: SocketAddr) -> Self {
        let context = Arc::new(Mutex::new(SessionContext::new(service_id, session_id)));

        let session = Session {
            context: context.clone(),
        };

        tokio::spawn(async move {
            let transport = SessionTransport::connect(context.clone(), addr);

            match transport.await {
                Ok(transport) => transport.await,
                Err(err) => context.lock().unwrap().set_error(err),
            }
        });

        session
    }

    /// Push a given Arrow Message into the output buffer.
    fn push(&mut self, msg: ArrowMessage) {
        self.context.lock().unwrap().push_output_message(msg)
    }

    /// Take an Arrow Message from the input buffer. The method returns:
    /// * `Poll::Ready(Some(Ok(_)))` if there was some data available
    /// * `Poll::Ready(None)` if there was no data available and the context
    ///   has been closed
    /// * `Poll::Pending` if there was no data available
    fn take(&mut self, cx: &mut Context) -> Poll<Option<Result<ArrowMessage, ConnectionError>>> {
        self.context.lock().unwrap().take_input_message(cx)
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
struct SessionTransport {
    context: Arc<Mutex<SessionContext>>,
    stream: TcpStream,
}

impl SessionTransport {
    /// Create a new session transport by connecting to a given host.
    async fn connect(
        context: Arc<Mutex<SessionContext>>,
        addr: SocketAddr,
    ) -> Result<Self, ConnectionError> {
        let stream = tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| ConnectionError::from("connection timeout"))?
            .map_err(ConnectionError::from)?;

        let transport = Self { context, stream };

        Ok(transport)
    }
}

impl Future for SessionTransport {
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
pub struct SessionManager {
    logger: BoxLogger,
    svc_table: BoxServiceTable,
    cmsg_factory: ControlMessageFactory,
    cmsg_queue: VecDeque<ArrowMessage>,
    sessions: HashMap<u32, Session>,
    poll_order: VecDeque<u32>,
    new_session: Option<Waker>,
}

impl SessionManager {
    /// Create a new session manager.
    pub fn new(app_context: ApplicationContext, cmsg_factory: ControlMessageFactory) -> Self {
        let svc_table = app_context.get_service_table();

        Self {
            logger: app_context.get_logger(),
            svc_table: svc_table.boxed(),
            cmsg_factory,
            cmsg_queue: VecDeque::new(),
            sessions: HashMap::new(),
            poll_order: VecDeque::new(),
            new_session: None,
        }
    }

    /// Get number of active sessions.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Send a given Arrow Message to the corresponding service using a given
    /// session (as specified by the message).
    pub fn send(&mut self, msg: ArrowMessage) {
        let header = msg.header();

        let session = self.take_session(header.service, header.session);

        if let Ok(mut session) = session {
            session.push(msg);

            self.sessions.insert(header.session, session);
        } else if let Err(err) = session {
            log_warn!(
                self.logger,
                "unable to connect to a remote service: {}",
                err.description()
            );

            let msg = self.create_hup_message(header.session, EC_CONNECTION_ERROR);

            self.cmsg_queue.push_back(msg);
        }
    }

    /// Close a given session.
    pub fn close(&mut self, session_id: u32, _: u32) {
        if let Some(mut session) = self.sessions.remove(&session_id) {
            log_info!(
                self.logger,
                "closing service connection; session ID: {:08x}",
                session_id
            );

            session.close();
        }
    }

    /// Take a given session object.
    fn take_session(&mut self, service_id: u16, session_id: u32) -> Result<Session, ArrowError> {
        let session = if let Some(session) = self.sessions.remove(&session_id) {
            session
        } else {
            let session = self.connect(service_id, session_id)?;
            self.poll_order.push_back(session_id);
            // notify the message consuming task
            if let Some(task) = self.new_session.take() {
                task.wake();
            }
            session
        };
        Ok(session)
    }

    /// Connect to a given service and create an associated session object
    /// with a given ID.
    fn connect(&mut self, service_id: u16, session_id: u32) -> Result<Session, ArrowError> {
        let svc = self
            .svc_table
            .get(service_id)
            .ok_or_else(|| ArrowError::other(format!("unknown service ID: {:04x}", service_id)))?;

        let addr = svc.address().ok_or_else(|| {
            ArrowError::other(format!(
                "there is no address for a given service; service ID: {:04x}",
                service_id
            ))
        })?;

        log_info!(
            self.logger,
            "connecting to remote service: {}, service ID: {:04x}, session ID: {:08x}",
            addr,
            service_id,
            session_id
        );

        Ok(Session::new(service_id, session_id, addr))
    }

    /// Create HUP message for a given session.
    fn create_hup_message(&mut self, session_id: u32, error_code: u32) -> ArrowMessage {
        log_debug!(
            self.logger,
            "sending a HUP message (session ID: {:08x}, error_code: {:08x})...",
            session_id,
            error_code
        );

        ArrowMessage::from(self.cmsg_factory.hup(session_id, error_code))
    }
}

impl Drop for SessionManager {
    fn drop(&mut self) {
        for (session_id, mut session) in self.sessions.drain() {
            log_info!(
                self.logger,
                "closing service connection; session ID: {:08x}",
                session_id
            );

            session.close();
        }
    }
}

impl Stream for SessionManager {
    type Item = Result<ArrowMessage, ArrowError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        if let Some(msg) = self.cmsg_queue.pop_front() {
            return Poll::Ready(Some(Ok(msg)));
        }

        let mut count = self.poll_order.len();

        while count > 0 {
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
                                "service connection closed; session ID: {:08x}",
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
                                "service connection error; session ID: {:08x}: {}",
                                session_id,
                                err.description()
                            );

                            let msg = self.create_hup_message(session_id, EC_CONNECTION_ERROR);

                            return Poll::Ready(Some(Ok(msg)));
                        }
                    }
                }
            }

            count -= 1;
        }

        // the session manager needs to be re-polled in case there is a new
        // session
        self.new_session = Some(cx.waker().clone());

        Poll::Pending
    }
}
