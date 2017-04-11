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
pub mod codec;
pub mod error;

mod session;

use std::io;

use std::rc::Rc;
use std::cell::Cell;
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

use net::arrow::proto::codec::{ArrowCodec, FromBytes};
use net::arrow::proto::error::ArrowError;
use net::arrow::proto::msg::ArrowMessage;
use net::arrow::proto::msg::control::{
    ACK_NO_ERROR,
    ACK_UNSUPPORTED_PROTOCOL_VERSION,
    ACK_UNAUTHORIZED,
    ACK_INTERNAL_SERVER_ERROR,

    AckMessage,
    ControlMessage,
    ControlMessageType,
    HupMessage,
    RedirectMessage
};
use net::arrow::proto::session::SessionManager;
use net::utils::Timeout;

pub use net::arrow::proto::msg::control::svc_table::{Service, ServiceTable};

use utils::logger::Logger;

/// Currently supported version of the Arrow protocol.
pub const ARROW_PROTOCOL_VERSION: u8 = 1;

const ACK_TIMEOUT: u64 = 20000;

/// Commands that might be sent by the Arrow Client into a given command queue.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Command {
    ResetServiceTable,
    ScanNetwork,
}

/// Common trait for various implementations of command senders.
pub trait Sender {
    /// Send a given command or return the command back if the send operation
    /// failed.
    fn send(&self, cmd: Command) -> Result<(), Command>;
}

/// Arrow Protocol states.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum ProtocolState {
    Handshake,
    Established
}

/// Arrow Client implementation.
struct ArrowClient<L, S> {
    logger:        L,
    cmd_sender:    S,
    tc_handle:     TokioCoreHandle,
    cmsg_factory:  ControlMessageFactory,
    sessions:      SessionManager,
    messages:      VecDeque<ArrowMessage>,
    expected_acks: VecDeque<u16>,
    ack_timeout:   Timeout,
    state:         ProtocolState,
    redirect:      Option<String>,
}

impl<L, S> ArrowClient<L, S>
    where L: Logger,
          S: Sender {
    /// Create a new Arrow Client.
    fn new<T>(
        logger: L,
        cmd_sender: S,
        svc_table: T,
        tc_handle: TokioCoreHandle) -> ArrowClient<L, S>
        where T: 'static + ServiceTable {
        let cmsg_factory = ControlMessageFactory::new();
        let session_manager = SessionManager::new(
            tc_handle.clone(),
            svc_table,
            cmsg_factory.clone());

        let messages = VecDeque::new();

        // TODO: add REGISTER message into the message queue

        ArrowClient {
            logger:        logger,
            cmd_sender:    cmd_sender,
            tc_handle:     tc_handle,
            cmsg_factory:  cmsg_factory,
            sessions:      session_manager,
            messages:      messages,
            expected_acks: VecDeque::new(),
            ack_timeout:   Timeout::new(),
            state:         ProtocolState::Handshake,
            redirect:      None,
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
    fn send_control_message(&mut self, msg: ControlMessage) {
        self.messages.push_back(ArrowMessage::new(0, 0, msg))
    }

    /// Process a given Control Protocol message.
    fn process_control_protocol_message(&mut self, msg: ArrowMessage) -> Result<(), ArrowError> {
        let msg = ControlMessage::from_bytes(msg.payload())?
            .expect("unable to decode an Arrow Control Protocol message");

        let header = msg.header();

        match header.message_type() {
            ControlMessageType::ACK             => self.process_ack_message(msg),
            ControlMessageType::PING            => self.process_ping_message(msg),
            ControlMessageType::HUP             => self.process_hup_message(msg),
            ControlMessageType::REDIRECT        => self.process_redirect_message(msg),
            ControlMessageType::GET_STATUS      => self.process_get_status_message(msg),
            ControlMessageType::GET_SCAN_REPORT => self.process_get_scan_report_message(msg),
            ControlMessageType::RESET_SVC_TABLE => self.process_command(Command::ResetServiceTable),
            ControlMessageType::SCAN_NETWORK    => self.process_command(Command::ScanNetwork),
            ControlMessageType::UNKNOWN
                => Err(ArrowError::from("unknow control message received")),
            _   => Err(ArrowError::from("unexpected control message received")),
        }
    }

    /// Process a given ACK message.
    fn process_ack_message(&mut self, msg: ControlMessage) -> Result<(), ArrowError> {
        let header = msg.header();

        let expected_ack = self.expected_acks.pop_front();

        if self.expected_acks.is_empty() {
            self.ack_timeout.clear();
        } else {
            self.ack_timeout.set(ACK_TIMEOUT);
        }

        if let Some(expected_ack) = expected_ack {
            if header.msg_id == expected_ack {
                if self.state == ProtocolState::Handshake {
                    self.process_handshake_ack(msg)
                } else {
                    Ok(())
                }
            } else {
                Err(ArrowError::from("unexpected ACK message ID"))
            }
        } else {
            Err(ArrowError::from("no ACK message expected"))
        }
    }

    /// Process handshake ACK.
    fn process_handshake_ack(&mut self, msg: ControlMessage) -> Result<(), ArrowError> {
        let ack = msg.body::<AckMessage>()
            .expect("ACK message expected");

        if ack.err == ACK_NO_ERROR {
            // switch the protocol state into normal operation
            self.state = ProtocolState::Established;

            // TODO: spawn job for periodical sending of UPDATE messages
            // TODO: spawn job for periodical sending of PING messages
            // TODO: get the diagnostic mode state
            let diagnostic_mode = false;

            // report a fake redirect in case of the diagnostic mode
            if diagnostic_mode {
                self.redirect = Some(String::new());
            }

            Ok(())
        } else if ack.err == ACK_UNAUTHORIZED {
            Err(ArrowError::from("Arrow REGISTER failed (unauthorized)"))
        } else if ack.err == ACK_UNSUPPORTED_PROTOCOL_VERSION {
            Err(ArrowError::from("Arrow REGISTER failed (unsupported version of the Arrow Protocol)"))
        } else if ack.err == ACK_INTERNAL_SERVER_ERROR {
            Err(ArrowError::from("Arrow REGISTER failed (internal server error)"))
        } else {
            Err(ArrowError::from("Arrow REGISTER failed (unknown error)"))
        }
    }

    /// Process a given PING message.
    fn process_ping_message(&mut self, msg: ControlMessage) -> Result<(), ArrowError> {
        let header = msg.header();

        self.send_control_message(
            ControlMessage::ack(header.msg_id, 0));

        Ok(())
    }

    /// Process a given HUP message.
    fn process_hup_message(&mut self, msg: ControlMessage) -> Result<(), ArrowError> {
        let hup = msg.body::<HupMessage>()
            .expect("HUP message expected");

        self.sessions.close(
            hup.session_id,
            hup.error_code);

        Ok(())
    }

    /// Process a given REDIRECT message.
    fn process_redirect_message(&mut self, msg: ControlMessage) -> Result<(), ArrowError> {
        let msg = msg.body::<RedirectMessage>()
            .expect("REDIRECT message expected");

        self.redirect = Some(msg.target.clone());

        Ok(())
    }

    /// Process a given GET_STATUS message.
    fn process_get_status_message(&mut self, _: ControlMessage) -> Result<(), ArrowError> {
        // TODO
        Ok(())
    }

    /// Process a given GET_SCAN_REPORT message.
    fn process_get_scan_report_message(&mut self, _: ControlMessage) -> Result<(), ArrowError> {
        // TODO
        Ok(())
    }

    /// Send a given command using the underlaying command channel.
    fn process_command(&mut self, cmd: Command) -> Result<(), ArrowError> {
        if let Err(cmd) = self.cmd_sender.send(cmd) {
            log_warn!(self.logger, "unable to process command {:?}", cmd);
        }

        Ok(())
    }

    /// Process a given service request message.
    fn process_service_request_message(&mut self, msg: ArrowMessage) -> Result<(), ArrowError> {
        if self.state != ProtocolState::Established {
            return Err(ArrowError::from("cannot handle service requests in the Handshake state"))
        }

        self.sessions.send(msg);

        Ok(())
    }
}

impl<L, S> Sink for ArrowClient<L, S>
    where L: Logger,
          S: Sender {
    type SinkItem  = ArrowMessage;
    type SinkError = ArrowError;

    fn start_send(&mut self, msg: ArrowMessage) -> StartSend<ArrowMessage, ArrowError> {
        // ignore the message if the client has been closed
        if self.is_closed() {
            return Ok(AsyncSink::Ready)
        }

        let header = msg.header();

        if header.service == 0 {
            self.process_control_protocol_message(msg)?;
        } else {
            self.process_service_request_message(msg)?;
        }

        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), ArrowError> {
        Ok(Async::Ready(()))
    }
}

impl<L, S> Stream for ArrowClient<L, S>
    where L: Logger,
          S: Sender {
    type Item  = ArrowMessage;
    type Error = ArrowError;

    fn poll(&mut self) -> Poll<Option<ArrowMessage>, ArrowError> {
        if self.is_closed() {
            Ok(Async::Ready(None))
        } else if let Some(msg) = self.messages.pop_front() {
            Ok(Async::Ready(Some(msg)))
        } else {
            self.sessions.poll()
        }
    }
}

/// Control Protocol message factory with shared message ID counter.
#[derive(Clone)]
pub struct ControlMessageFactory {
    counter: Rc<Cell<u16>>,
}

impl ControlMessageFactory {
    /// Create a new Control Protocol message factory.
    pub fn new() -> ControlMessageFactory {
        ControlMessageFactory {
            counter: Rc::new(Cell::new(0)),
        }
    }

    /// Get next message ID and increment the counter.
    fn next_id(&mut self) -> u16 {
        let res = self.counter.get();

        self.counter.set(res.wrapping_add(1));

        res
    }

    /// Create a new ACK message with a given error code.
    pub fn ack(&mut self, error_code: u32) -> ArrowMessage {
        ArrowMessage::from(
            ControlMessage::ack(
                    self.next_id(),
                    error_code))
    }

    /// Create a new HUP message with a given session ID and error code.
    pub fn hup(&mut self, session_id: u32, error_code: u32) -> ArrowMessage {
        ArrowMessage::from(
            ControlMessage::hup(
                self.next_id(),
                session_id,
                error_code))
    }
}

/// Connect Arrow Client to a given address and return either a redirect address or an error.
pub fn connect<L, S, T>(
    logger: L,
    cmd_sender: S,
    svc_table: T,
    addr: &str) -> Result<String, ArrowError>
    where L: Logger,
          S: Sender,
          T: 'static + ServiceTable {
    let mut core = TokioCore::new()?;

    let addr = addr.to_socket_addrs()?
        .next()
        .ok_or(io::Error::new(io::ErrorKind::Other, "unable to resolve a given address"))?;

    let aclient = ArrowClient::new(
        logger,
        cmd_sender,
        svc_table,
        core.handle());

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
