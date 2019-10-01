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
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{Bytes, BytesMut};

use futures::task;

use futures::sink::Sink;
use futures::stream::Stream;
use futures::task::Task;
use futures::{Async, AsyncSink, Future, Poll, StartSend};

use tokio;

use tokio::codec::Decoder;
use tokio::net::TcpStream;
use tokio::timer::Timeout;

use crate::context::ApplicationContext;
use crate::futures_ex::StreamEx;
use crate::net::arrow::error::{ArrowError, ConnectionError};
use crate::net::arrow::proto::codec::RawCodec;
use crate::net::arrow::proto::msg::control::{
    ControlMessageFactory, EC_CONNECTION_ERROR, EC_NO_ERROR,
};
use crate::net::arrow::proto::msg::ArrowMessage;
use crate::svc_table::{BoxServiceTable, ServiceTable};
use crate::utils::logger::{BoxLogger, Logger};

const INPUT_BUFFER_LIMIT: usize = 32768;
const OUTPUT_BUFFER_LIMIT: usize = 4 * 1024 * 1024;

const CONNECTION_TIMEOUT: u64 = 20;

/// Session context.
struct SessionContext {
    service_id: u16,
    session_id: u32,
    input: BytesMut,
    output: BytesMut,
    input_ready: Option<Task>,
    input_empty: Option<Task>,
    output_ready: Option<Task>,
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
            input_ready: None,
            input_empty: None,
            output_ready: None,
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

            // we MUST notify any possible task consuming the output buffer that
            // there is some data available again
            if !self.output.is_empty() {
                if let Some(task) = self.output_ready.take() {
                    task.notify();
                }
            }
        }
    }

    /// Take all the data from the input buffer and return them as an Arrow
    /// Message. The method returns:
    /// * `Async::Ready(Some(_))` if there was some data available
    /// * `Async::Ready(None)` if there was no data available and the context
    ///   has been closed
    /// * `Async::NotReady` if there was no data available
    fn take_input_message(&mut self) -> Poll<Option<ArrowMessage>, ConnectionError> {
        let data = self.input.take().freeze();

        // we MUST notify any possible task feeding the input buffer that the
        // buffer is empty again
        if let Some(task) = self.input_empty.take() {
            task.notify();
        }

        if !data.is_empty() {
            let message = ArrowMessage::new(self.service_id, self.session_id, data);

            Ok(Async::Ready(Some(message)))
        } else if self.closed {
            match self.error.take() {
                Some(err) => Err(err),
                None => Ok(Async::Ready(None)),
            }
        } else {
            // save the current task and wait until there is some data
            // available in the input buffer
            self.input_ready = Some(task::current());

            Ok(Async::NotReady)
        }
    }

    /// Extend the input buffer with given data. The method returns:
    /// * `AsyncSink::NotReady(_)` with remaining data if the input buffer is
    ///   full
    /// * `AsyncSink::Ready` if all the given data has been inserted into the
    ///   input buffer
    /// * an error if the context has been closed
    fn push_input_data(&mut self, mut msg: Bytes) -> StartSend<Bytes, ConnectionError> {
        if self.closed {
            return Err(ConnectionError::from("connection has been closed"));
        }

        let mut take = msg.len();

        if (take + self.input.len()) > INPUT_BUFFER_LIMIT {
            take = INPUT_BUFFER_LIMIT - self.input.len();
        }

        self.input.extend_from_slice(&msg.split_to(take));

        // we MUST notify any possible task consuming the input buffer that
        // there is some data available again
        if !self.input.is_empty() {
            if let Some(task) = self.input_ready.take() {
                task.notify();
            }
        }

        if msg.is_empty() {
            Ok(AsyncSink::Ready)
        } else {
            // save the current task and wait until there is some space in
            // the input buffer again
            self.input_empty = Some(task::current());

            Ok(AsyncSink::NotReady(msg))
        }
    }

    /// Flush the input buffer. The method returns:
    /// * `Async::Ready(())` if the input buffer is empty
    /// * `Async::NotReady` if the buffer is not empty
    fn flush_input_buffer(&mut self) -> Poll<(), ConnectionError> {
        if self.input.is_empty() {
            Ok(Async::Ready(()))
        } else {
            // save the current task and wait until the input buffer is empty
            self.input_empty = Some(task::current());

            Ok(Async::NotReady)
        }
    }

    /// Take data from the output buffer. The method returns:
    /// * `Async::Ready(Some(_))` if there is some data available
    /// * `Async::Ready(None)` if the context has been closed and there is
    ///   not data in the output buffer
    /// * `Async::NotReady` if there is no data available
    fn take_output_data(&mut self) -> Poll<Option<Bytes>, ConnectionError> {
        let data = self.output.take().freeze();

        if !data.is_empty() {
            Ok(Async::Ready(Some(data)))
        } else if self.closed {
            Ok(Async::Ready(None))
        } else {
            // save the current task and wait until there is some data in
            // the output buffer available again
            self.output_ready = Some(task::current());

            Ok(Async::NotReady)
        }
    }

    /// Mark the context as closed. Note that this method does not flush any
    /// buffer.
    fn close(&mut self) {
        self.closed = true;

        // we MUST notify any possible task consuming the output buffer that
        // the connection was closed and that there will be no more output data
        if let Some(task) = self.output_ready.take() {
            task.notify();
        }

        // we MUST notify any possible task consuming the input buffer that
        // the connection was closed and that there will be no more input data
        if let Some(task) = self.input_ready.take() {
            task.notify();
        }
    }

    /// Mark the context as closed and set a given error. Note that this
    /// method does not flush any buffer.
    fn set_error(&mut self, err: ConnectionError) {
        // ignore all errors after the connection gets closed
        if !self.closed {
            self.closed = true;
            self.error = Some(err);
        }
    }
}

/// Arrow session (i.e. connection to an external service).
struct Session {
    context: Arc<Mutex<SessionContext>>,
}

impl Session {
    /// Create a new session for a given service ID and session ID.
    fn new(service_id: u16, session_id: u32) -> Self {
        let context = SessionContext::new(service_id, session_id);

        Self {
            context: Arc::new(Mutex::new(context)),
        }
    }

    /// Push a given Arrow Message into the output buffer.
    fn push(&mut self, msg: ArrowMessage) {
        self.context.lock().unwrap().push_output_message(msg)
    }

    /// Take an Arrow Message from the input buffer. The method returns:
    /// * `Async::Ready(Some(_))` if there was some data available
    /// * `Async::Ready(None)` if there was no data available and the context
    ///   has been closed
    /// * `Async::NotReady` if there was no data available
    fn take(&mut self) -> Poll<Option<ArrowMessage>, ConnectionError> {
        self.context.lock().unwrap().take_input_message()
    }

    /// Mark the session as closed. The session context won't accept any new
    /// data, however the buffered data can be still processed. It's up to
    /// the corresponding tasks to consume all remaining data.
    fn close(&mut self) {
        self.context.lock().unwrap().close()
    }

    /// Get session transport.
    fn transport(&self) -> SessionTransport {
        SessionTransport {
            context: self.context.clone(),
        }
    }

    /// Get session error handler.
    fn error_handler(&self) -> SessionErrorHandler {
        SessionErrorHandler {
            context: self.context.clone(),
        }
    }
}

/// Session transport.
struct SessionTransport {
    context: Arc<Mutex<SessionContext>>,
}

impl Stream for SessionTransport {
    type Item = Bytes;
    type Error = ConnectionError;

    fn poll(&mut self) -> Poll<Option<Bytes>, ConnectionError> {
        self.context.lock().unwrap().take_output_data()
    }
}

impl Sink for SessionTransport {
    type SinkItem = Bytes;
    type SinkError = ConnectionError;

    fn start_send(&mut self, data: Bytes) -> StartSend<Bytes, ConnectionError> {
        self.context.lock().unwrap().push_input_data(data)
    }

    fn poll_complete(&mut self) -> Poll<(), ConnectionError> {
        self.context.lock().unwrap().flush_input_buffer()
    }

    fn close(&mut self) -> Poll<(), ConnectionError> {
        let mut context = self.context.lock().unwrap();

        // mark the context as closed
        context.close();

        // and wait until the input buffer is fully consumed
        context.flush_input_buffer()
    }
}

/// Session error handler.
struct SessionErrorHandler {
    context: Arc<Mutex<SessionContext>>,
}

impl SessionErrorHandler {
    /// Save a given transport error into the session context.
    fn set_error(&mut self, err: ConnectionError) {
        self.context.lock().unwrap().set_error(err)
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
    new_session: Option<Task>,
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
                task.notify();
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

        let session = Session::new(service_id, session_id);
        let transport = session.transport();
        let mut err_handler = session.error_handler();

        let connection = TcpStream::connect(&addr);

        let timeout = Duration::from_secs(CONNECTION_TIMEOUT);

        let client = Timeout::new(connection, timeout)
            .map_err(|err| {
                if err.is_elapsed() {
                    ConnectionError::from("connection timeout")
                } else if let Some(inner) = err.into_inner() {
                    ConnectionError::from(inner)
                } else {
                    ConnectionError::from("timer error")
                }
            })
            .and_then(|stream| {
                let framed = RawCodec.framed(stream);

                let (sink, stream) = framed.split();

                let messages = stream.pipe(transport);

                sink.send_all(messages)
            })
            .then(move |res| {
                if let Err(err) = res {
                    err_handler.set_error(err);
                }

                Ok(())
            });

        tokio::spawn(client);

        Ok(session)
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
    type Item = ArrowMessage;
    type Error = ArrowError;

    fn poll(&mut self) -> Poll<Option<ArrowMessage>, ArrowError> {
        if let Some(msg) = self.cmsg_queue.pop_front() {
            return Ok(Async::Ready(Some(msg)));
        }

        let mut count = self.poll_order.len();

        while count > 0 {
            if let Some(session_id) = self.poll_order.pop_front() {
                if let Some(mut session) = self.sessions.remove(&session_id) {
                    match session.take() {
                        Ok(Async::NotReady) => {
                            self.sessions.insert(session_id, session);
                            self.poll_order.push_back(session_id);
                        }
                        Ok(Async::Ready(None)) => {
                            log_info!(
                                self.logger,
                                "service connection closed; session ID: {:08x}",
                                session_id
                            );

                            let msg = self.create_hup_message(session_id, EC_NO_ERROR);

                            return Ok(Async::Ready(Some(msg)));
                        }
                        Ok(Async::Ready(Some(msg))) => {
                            self.sessions.insert(session_id, session);
                            self.poll_order.push_back(session_id);

                            return Ok(Async::Ready(Some(msg)));
                        }
                        Err(err) => {
                            log_warn!(
                                self.logger,
                                "service connection error; session ID: {:08x}: {}",
                                session_id,
                                err.description()
                            );

                            let msg = self.create_hup_message(session_id, EC_CONNECTION_ERROR);

                            return Ok(Async::Ready(Some(msg)));
                        }
                    }
                }
            }

            count -= 1;
        }

        // the session manager needs to be re-polled in case there is a new
        // session
        self.new_session = Some(task::current());

        Ok(Async::NotReady)
    }
}
