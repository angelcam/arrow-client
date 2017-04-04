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

pub mod msg;
pub mod buffer;
pub mod codec;
pub mod error;

use std::io;

use std::net::ToSocketAddrs;
use std::collections::VecDeque;

use futures::{StartSend, Async, AsyncSink, Poll};
use futures::future::Future;
use futures::stream::Stream;
use futures::sink::Sink;

use tokio_core::net::TcpStream;
use tokio_core::reactor::Core as TokioCore;
use tokio_core::reactor::Handle as TokioCoreHandle;

use tokio_io::AsyncRead;

use futures_ex::StreamEx;

use net::arrow::proto::codec::ArrowCodec;
use net::arrow::proto::error::ArrowError;
use net::arrow::proto::msg::ArrowMessage;
use net::arrow::proto::msg::control::{ControlMessage, ControlMessageType, RedirectMessage};

/// Currently supported version of the Arrow protocol.
pub const ARROW_PROTOCOL_VERSION: u8 = 1;

/// Arrow Client implementation.
struct ArrowClient {
    tc_handle: TokioCoreHandle,
    messages:  VecDeque<ArrowMessage>,
    redirect:  Option<String>,
}

impl ArrowClient {
    /// Create a new Arrow Client.
    fn new(tc_handle: TokioCoreHandle) -> ArrowClient {
        ArrowClient {
            tc_handle: tc_handle,
            messages:  VecDeque::new(),
            redirect:  None,
        }
    }

    /// Get redirect address (if any).
    fn get_redirect(&self) -> Option<&str> {
        self.redirect.as_ref()
            .map(|r| r as &str)
    }

    /// Check if the client has been closed.
    fn is_closed(&self) -> bool {
        self.redirect.is_some()
    }

    /// Insert a given Control Protocol message into the output message queue.
    fn send_control_protocol_message(&mut self, msg: ControlMessage) {
        self.messages.push_back(ArrowMessage::new(0, 0, msg))
    }

    /// Process a given Control Protocol message.
    fn process_control_protocol_message(&mut self, msg: &ArrowMessage) -> Result<(), ArrowError> {
        let msg = msg.body::<ControlMessage>()
            .expect("control protocol message expected");

        let header = msg.header();

        match header.message_type() {
            ControlMessageType::ACK             => self.process_ack_message(msg),
            ControlMessageType::PING            => self.process_ping_message(msg),
            ControlMessageType::HUP             => self.process_hup_message(msg),
            ControlMessageType::REDIRECT        => self.process_redirect_message(msg),
            ControlMessageType::GET_STATUS      => self.process_get_status_message(msg),
            ControlMessageType::GET_SCAN_REPORT => self.process_get_scan_report_message(msg),
            ControlMessageType::RESET_SVC_TABLE => self.process_reset_svc_table_message(msg),
            ControlMessageType::SCAN_NETWORK    => self.process_scan_network_message(msg),
            ControlMessageType::UNKNOWN
                => Err(ArrowError::from("unknow control message received")),
            _   => Err(ArrowError::from("unexpected control message received")),
        }
    }

    /// Process a given ACK message.
    fn process_ack_message(&mut self, _: &ControlMessage) -> Result<(), ArrowError> {
        // TODO
        Ok(())
    }

    /// Process a given PING message.
    fn process_ping_message(&mut self, msg: &ControlMessage) -> Result<(), ArrowError> {
        let header = msg.header();

        self.send_control_protocol_message(
            ControlMessage::ack(header.msg_id, 0));

        Ok(())
    }

    /// Process a given HUP message.
    fn process_hup_message(&mut self, _: &ControlMessage) -> Result<(), ArrowError> {
        // TODO
        Ok(())
    }

    /// Process a given REDIRECT message.
    fn process_redirect_message(&mut self, msg: &ControlMessage) -> Result<(), ArrowError> {
        let msg = msg.body::<RedirectMessage>()
            .expect("REDIRECT message expected");

        self.redirect = Some(msg.target.clone());

        Ok(())
    }

    /// Process a given GET_STATUS message.
    fn process_get_status_message(&mut self, _: &ControlMessage) -> Result<(), ArrowError> {
        // TODO
        Ok(())
    }

    /// Process a given GET_SCAN_REPORT message.
    fn process_get_scan_report_message(&mut self, _: &ControlMessage) -> Result<(), ArrowError> {
        // TODO
        Ok(())
    }

    /// Process a given RESET_SVC_TABLE message.
    fn process_reset_svc_table_message(&mut self, _: &ControlMessage) -> Result<(), ArrowError> {
        // TODO
        Ok(())
    }

    /// Process a given SCAN_NETWORK message.
    fn process_scan_network_message(&mut self, _: &ControlMessage) -> Result<(), ArrowError> {
        // TODO
        Ok(())
    }

    /// Process a given service request message.
    fn process_service_request_message(&mut self, _: &ArrowMessage) -> Result<(), ArrowError> {
        // TODO
        Ok(())
    }
}

impl Sink for ArrowClient {
    type SinkItem  = ArrowMessage;
    type SinkError = ArrowError;

    fn start_send(&mut self, msg: ArrowMessage) -> StartSend<ArrowMessage, ArrowError> {
        // ignore the message if the client has been closed
        if self.is_closed() {
            return Ok(AsyncSink::Ready)
        }

        let header = msg.header();

        if header.service == 0 {
            self.process_control_protocol_message(&msg)?;
        } else {
            self.process_service_request_message(&msg)?;
        }

        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), ArrowError> {
        Ok(Async::Ready(()))
    }
}

impl Stream for ArrowClient {
    type Item  = ArrowMessage;
    type Error = ArrowError;

    fn poll(&mut self) -> Poll<Option<ArrowMessage>, ArrowError> {
        if self.is_closed() {
            Ok(Async::Ready(None))
        } else if let Some(msg) = self.messages.pop_front() {
            Ok(Async::Ready(Some(msg)))
        } else {
            Ok(Async::NotReady)
        }
    }
}

/// Connect Arrow Client to a given address and return either a redirect address or an error.
pub fn connect(addr: &str) -> Result<String, ArrowError> {
    let mut core = TokioCore::new()?;

    let addr = addr.to_socket_addrs()?
        .next()
        .ok_or(io::Error::new(io::ErrorKind::Other, "unable to resolve a given address"))?;

    let aclient = ArrowClient::new(core.handle());

    let client = TcpStream::connect(&addr, &core.handle())
        .map_err(|err| ArrowError::from(err))
        .and_then(|stream| {
            let framed = stream.framed(ArrowCodec);
            let (sink, stream) = framed.split();

            let messages = stream.pipe(aclient);

            sink.send_all(messages)
                .and_then(|(_, pipe)| {
                    let (_, _, context) = pipe.unpipe();
                    let redirect = context.get_redirect()
                        .expect("connection closed, redirect expected")
                        .to_string();

                    Ok(redirect)
                })
        });

    core.run(client)
}
