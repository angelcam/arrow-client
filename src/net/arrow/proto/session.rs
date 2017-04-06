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

use std::rc::Rc;
use std::cell::RefCell;

use bytes::{Bytes, BytesMut};

use futures::task;

use futures::{StartSend, Async, AsyncSink, Poll};
use futures::task::Task;
use futures::stream::Stream;
use futures::sink::Sink;

use tokio_io::codec::{Decoder, Encoder};

use net::arrow::proto::msg::ArrowMessage;

/// Simple raw codec used for service connections.
pub struct RawCodec;

impl Decoder for RawCodec {
    type Item = Bytes;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let bytes = src.take()
            .freeze();

        if bytes.len() > 0 {
            Ok(Some(bytes))
        } else {
            Ok(None)
        }
    }
}

impl Encoder for RawCodec {
    type Item = Bytes;
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.extend(item);
        Ok(())
    }
}

const INPUT_BUFFER_LIMIT: usize  = 32768;
const OUTPUT_BUFFER_LIMIT: usize = 4 * 1024 * 1024 * 1024;

/// Session context.
struct SessionContext {
    service_id:   u16,
    session_id:   u32,
    input:        BytesMut,
    output:       BytesMut,
    input_ready:  Option<Task>,
    input_empty:  Option<Task>,
    output_ready: Option<Task>,
    closed:       bool,
}

impl SessionContext {
    /// Create a new session context for a given service ID and session ID.
    fn new(service_id: u16, session_id: u32) -> SessionContext {
        SessionContext {
            service_id:   service_id,
            session_id:   session_id,
            input:        BytesMut::with_capacity(8192),
            output:       BytesMut::with_capacity(8192),
            input_ready:  None,
            input_empty:  None,
            output_ready: None,
            closed:       false,
        }
    }

    /// Extend the output buffer with data from a given Arrow Message. The
    /// method returns:
    /// * `()` on success
    /// * an error if the context has been closed or the output buffer hard
    ///   limit has been exceeded
    fn push_output_message(&mut self, msg: ArrowMessage) -> io::Result<()> {
        if self.closed {
            return Err(io::Error::new(io::ErrorKind::ConnectionReset, "connection has been closed"))
        }

        let data = msg.body::<Bytes>()
            .expect("bytes expected");

        // we cannot backpressure here, so we'll return an error if size
        // of the output buffer gets greater than a given hard limit
        if (self.output.len() + data.len()) > OUTPUT_BUFFER_LIMIT {
            return Err(io::Error::new(io::ErrorKind::Other, "output buffer limit exceeded"))
        }

        self.output.extend(data);

        // we MUST notify any possible task consuming the output buffer that
        // there is some data available again
        if self.output.len() > 0 {
            if let Some(task) = self.output_ready.take() {
                task.unpark();
            }
        }

        Ok(())
    }

    /// Take all the data from the input buffer and return them as an Arrow
    /// Message. The method returns:
    /// * `Async::Ready(Some(_))` if there was some data available
    /// * `Async::Ready(None)` if there was no data available and the context
    ///   has been closed
    /// * `Async::NotReady` if there was no data available
    fn take_input_message(&mut self) -> Poll<Option<ArrowMessage>, io::Error> {
        let data = self.input.take()
            .freeze();

        // we MUST notify any possible task feeding the input buffer that the
        // buffer is empty again
        if let Some(task) = self.input_empty.take() {
            task.unpark();
        }

        if data.len() > 0 {
            let message = ArrowMessage::new(
                self.service_id,
                self.session_id,
                data);

            Ok(Async::Ready(Some(message)))
        } else if self.closed {
            Ok(Async::Ready(None))
        } else {
            // park the current task and wait until there is some data
            // available in the input buffer
            self.input_ready = Some(task::park());

            Ok(Async::NotReady)
        }
    }

    /// Extend the input buffer with given data. The method returns:
    /// * `AsyncSink::NotReady(_)` with remaining data if the input buffer is
    ///   full
    /// * `AsyncSink::Ready` if all the given data has been inserted into the
    ///   input buffer
    /// * an error if the context has been closed
    fn push_input_data(&mut self, mut msg: Bytes) -> StartSend<Bytes, io::Error> {
        if self.closed {
            return Err(io::Error::new(io::ErrorKind::ConnectionReset, "connection has been closed"))
        }

        let mut take = msg.len();

        if (take + self.input.len()) > INPUT_BUFFER_LIMIT {
            take = INPUT_BUFFER_LIMIT - self.input.len();
        }

        self.input.extend(msg.split_to(take));

        // we MUST notify any possible task consuming the input buffer that
        // there is some data available again
        if self.input.len() > 0 {
            if let Some(task) = self.input_ready.take() {
                task.unpark();
            }
        }

        if msg.len() > 0 {
            // park the current task and wait until there is some space in
            // the input buffer again
            self.input_empty = Some(task::park());

            Ok(AsyncSink::NotReady(msg))
        } else {
            Ok(AsyncSink::Ready)
        }
    }

    /// Flush the input buffer. The method returns:
    /// * `Async::Ready(())` if the input buffer is empty
    /// * `Async::NotReady` if the buffer is not empty
    fn flush_input_buffer(&mut self) -> Poll<(), io::Error> {
        if self.input.len() > 0 {
            // park the current task and wait until the input buffer is empty
            self.input_empty = Some(task::park());

            Ok(Async::NotReady)
        } else {
            Ok(Async::Ready(()))
        }
    }

    /// Take data from the output buffer. The method returns:
    /// * `Async::Ready(Some(_))` if there is some data available
    /// * `Async::Ready(None)` if the context has been closed and there is
    ///   not data in the output buffer
    /// * `Async::NotReady` if there is no data available
    fn take_output_data(&mut self) -> Poll<Option<Bytes>, io::Error> {
        let data = self.output.take()
            .freeze();

        if data.len() > 0 {
            Ok(Async::Ready(Some(data)))
        } else if self.closed {
            Ok(Async::Ready(None))
        } else {
            // park the current task and wait until there is some data in
            // the output buffer available again
            self.output_ready = Some(task::park());

            Ok(Async::NotReady)
        }
    }

    /// Mark the context as closed. Note that this method does not flush any
    /// buffer.
    fn close(&mut self) {
        self.closed = true;
    }
}

/// Arrow session (i.e. connection to an external service).
pub struct Session {
    context: Rc<RefCell<SessionContext>>,
}

impl Session {
    /// Create a new session for a given service ID and session ID.
    pub fn new(service_id: u16, session_id: u32) -> Session {
        let context = SessionContext::new(service_id, session_id);

        Session {
            context: Rc::new(RefCell::new(context))
        }
    }

    /// Push a given Arrow Message into the output buffer. The method returns:
    /// * `()` on success
    /// * an error if the session has been closed or the output buffer hard
    ///   limit has been exceeded
    pub fn push(&mut self, msg: ArrowMessage) -> io::Result<()> {
        self.context.borrow_mut()
            .push_output_message(msg)
    }

    /// Take an Arrow Message from the input buffer. The method returns:
    /// * `Async::Ready(Some(_))` if there was some data available
    /// * `Async::Ready(None)` if there was no data available and the context
    ///   has been closed
    /// * `Async::NotReady` if there was no data available
    pub fn take(&mut self) -> Poll<Option<ArrowMessage>, io::Error> {
        self.context.borrow_mut()
            .take_input_message()
    }

    /// Mark the session as closed. The session context won't accept any new
    /// data, however the buffered data can be still processed. It's up to
    /// the corresponding tasks to consume all remaining data.
    pub fn close(&mut self) {
        self.context.borrow_mut()
            .close()
    }

    /// Get session transport.
    pub fn transport(&self) -> SessionTransport {
        SessionTransport {
            context: self.context.clone()
        }
    }
}

/// Session transport.
pub struct SessionTransport {
    context: Rc<RefCell<SessionContext>>,
}

impl Sink for SessionTransport {
    type SinkItem  = Bytes;
    type SinkError = io::Error;

    fn start_send(&mut self, data: Bytes) -> StartSend<Bytes, io::Error> {
        self.context.borrow_mut()
            .push_input_data(data)
    }

    fn poll_complete(&mut self) -> Poll<(), io::Error> {
        self.context.borrow_mut()
            .flush_input_buffer()
    }

    fn close(&mut self) -> Poll<(), io::Error> {
        let mut context = self.context.borrow_mut();

        // mark the context as closed
        context.close();

        // and wait until the input buffer is fully consumed
        context.flush_input_buffer()
    }
}

impl Stream for SessionTransport {
    type Item  = Bytes;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Bytes>, io::Error> {
        self.context.borrow_mut()
            .take_output_data()
    }
}
