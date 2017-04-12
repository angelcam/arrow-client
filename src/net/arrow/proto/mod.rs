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
mod utils;

use std::rc::Rc;
use std::cell::RefCell;
use std::net::ToSocketAddrs;
use std::collections::VecDeque;
use std::time::Duration;

use time;

use futures::task;

use futures::{StartSend, Async, AsyncSink, Poll};
use futures::future::Future;
use futures::stream::Stream;
use futures::sink::Sink;
use futures::task::Task;

use tokio_core::net::TcpStream;
use tokio_core::reactor::Core as TokioCore;
use tokio_core::reactor::Handle as TokioCoreHandle;

use tokio_io::AsyncRead;

use tokio_timer::Timer;

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
    RedirectMessage,

    ServiceTable,
    ScanReport,
};
use net::arrow::proto::session::SessionManager;
use net::arrow::proto::utils::ControlMessageFactory;

use utils::logger::Logger;

/// Currently supported version of the Arrow protocol.
pub const ARROW_PROTOCOL_VERSION: u8 = 1;

const ACK_TIMEOUT:         f64 = 20.0;
const PING_PERIOD:         f64 = 60.0;
const UPDATE_CHECK_PERIOD: f64 =  5.0;

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

/// Helper struct for expected ACK messages.
struct ExpectedAck {
    timestamp:  f64,
    message_id: u16,
}

impl ExpectedAck {
    /// Create a new ACK message expectation.
    fn new(message_id: u16) -> ExpectedAck {
        ExpectedAck {
            timestamp:  time::precise_time_s(),
            message_id: message_id,
        }
    }

    /// Check if it's too late for the ACK.
    fn timeout(&self) -> bool {
        (self.timestamp + ACK_TIMEOUT) < time::precise_time_s()
    }
}

/// Arrow Client implementation.
struct ArrowClientContext<L, S> {
    logger:           L,
    cmd_sender:       S,
    tc_handle:        TokioCoreHandle,
    cmsg_factory:     ControlMessageFactory,
    sessions:         SessionManager<L>,
    messages:         VecDeque<ArrowMessage>,
    expected_acks:    VecDeque<ExpectedAck>,
    state:            ProtocolState,
    task:             Option<Task>,
    redirect:         Option<String>,
    last_ping:        f64,
    last_update_chck: f64,
}

impl<L, S> ArrowClientContext<L, S>
    where L: Logger + Clone,
          S: Sender {
    /// Create a new Arrow Client.
    fn new<T>(
        mut logger: L,
        cmd_sender: S,
        svc_table: T,
        tc_handle: TokioCoreHandle) -> ArrowClientContext<L, S>
        where T: 'static + ServiceTable {
        let cmsg_factory = ControlMessageFactory::new();
        let session_manager = SessionManager::new(
            logger.clone(),
            svc_table,
            cmsg_factory.clone(),
            tc_handle.clone());

        let messages = VecDeque::new();

        log_debug!(logger, "sending REGISTER request...");

        // TODO: add REGISTER message into the message queue

        let t = time::precise_time_s();

        ArrowClientContext {
            logger:           logger,
            cmd_sender:       cmd_sender,
            tc_handle:        tc_handle,
            cmsg_factory:     cmsg_factory,
            sessions:         session_manager,
            messages:         messages,
            expected_acks:    VecDeque::new(),
            state:            ProtocolState::Handshake,
            task:             None,
            redirect:         None,
            last_ping:        t,
            last_update_chck: t,
        }
    }
}

impl<L, S> ArrowClientContext<L, S>
    where L: Logger,
          S: Sender {
    /// Get redirect address (if any).
    fn get_redirect(&self) -> Option<String> {
        self.redirect.as_ref()
            .map(|r| r.clone())
    }

    /// Check if the client has been closed.
    fn is_closed(&self) -> bool {
        self.redirect.is_some()
    }

    /// Check if there is an ACK timeout.
    fn ack_timeout(&self) -> bool {
        match self.expected_acks.front() {
            Some(ref expected_ack) => expected_ack.timeout(),
            None => false,
        }
    }

    /// Trigger all periodical tasks.
    fn time_event(&mut self) -> Result<(), ArrowError> {
        let t = time::precise_time_s();

        if self.state == ProtocolState::Established {
            if (self.last_ping + PING_PERIOD) < t {
                self.send_ping_message();
            }

            if (self.last_update_chck + UPDATE_CHECK_PERIOD) < t {
                self.check_for_updates();
            }

            // if there is an ACK timeout and the task consuming Arrow
            // Messages has been parked, unpark it
            if self.ack_timeout() {
                if let Some(task) = self.task.take() {
                    task.unpark();
                }
            }
        }

        Ok(())
    }

    /// Check if the service table has been updated.
    fn check_for_updates(&mut self) {
        // TODO

        self.last_update_chck = time::precise_time_s();
    }

    /// Insert a given Control Protocol message into the output message queue.
    fn send_control_message(&mut self, msg: ControlMessage) {
        self.messages.push_back(ArrowMessage::from(msg))
    }

    /// Insert a given Control Protocol message into the output message queue
    /// and register an expected ACK.
    fn send_unconfirmed_control_message(&mut self, msg: ControlMessage) {
        let header = msg.header();

        self.expected_acks.push_back(
            ExpectedAck::new(header.msg_id));

        self.send_control_message(msg);
    }

    /// Send PING message.
    fn send_ping_message(&mut self) {
        log_debug!(self.logger, "sending a PING message...");

        let msg = self.cmsg_factory.ping();

        self.send_unconfirmed_control_message(msg);

        self.last_ping = time::precise_time_s();
    }

    /// Process a given Control Protocol message.
    fn process_control_protocol_message(&mut self, msg: ArrowMessage) -> Result<(), ArrowError> {
        let msg = ControlMessage::from_bytes(msg.payload())?
            .expect("unable to decode an Arrow Control Protocol message");

        let header = msg.header();

        log_debug!(self.logger, "received control message: {:?}", header.message_type());

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
                => Err(ArrowError::other(format!("unknow control message received"))),
            mt  => Err(ArrowError::other(format!("unexpected control message received: {:?}", mt))),
        }
    }

    /// Process a given ACK message.
    fn process_ack_message(&mut self, msg: ControlMessage) -> Result<(), ArrowError> {
        let header = msg.header();

        if let Some(expected_ack) = self.expected_acks.pop_front() {
            if header.msg_id == expected_ack.message_id {
                if self.state == ProtocolState::Handshake {
                    self.process_handshake_ack(msg)
                } else {
                    Ok(())
                }
            } else {
                Err(ArrowError::other("unexpected ACK message ID"))
            }
        } else {
            Err(ArrowError::other("no ACK message expected"))
        }
    }

    /// Process handshake ACK.
    fn process_handshake_ack(&mut self, msg: ControlMessage) -> Result<(), ArrowError> {
        let ack = msg.body::<AckMessage>()
            .expect("ACK message expected");

        if ack.err == ACK_NO_ERROR {
            // switch the protocol state into normal operation
            self.state = ProtocolState::Established;

            // TODO: get the diagnostic mode state
            let diagnostic_mode = false;

            // report a fake redirect in case of the diagnostic mode
            if diagnostic_mode {
                self.redirect = Some(String::new());
            }

            Ok(())
        } else if ack.err == ACK_UNAUTHORIZED {
            Err(ArrowError::unauthorized("Arrow REGISTER failed (unauthorized)"))
        } else if ack.err == ACK_UNSUPPORTED_PROTOCOL_VERSION {
            Err(ArrowError::unsupported_protocol_version("Arrow REGISTER failed (unsupported version of the Arrow Protocol)"))
        } else if ack.err == ACK_INTERNAL_SERVER_ERROR {
            Err(ArrowError::arrow_server_error("Arrow REGISTER failed (internal server error)"))
        } else {
            Err(ArrowError::other("Arrow REGISTER failed (unknown error)"))
        }
    }

    /// Process a given PING message.
    fn process_ping_message(&mut self, msg: ControlMessage) -> Result<(), ArrowError> {
        if self.state != ProtocolState::Established {
            return Err(ArrowError::other("cannot handle PING message in the Handshake state"))
        }

        let header = msg.header();

        log_debug!(self.logger, "sending an ACK message...");

        let ack = self.cmsg_factory.ack(
            header.msg_id,
            0x00);

        self.send_control_message(ack);

        Ok(())
    }

    /// Process a given HUP message.
    fn process_hup_message(&mut self, msg: ControlMessage) -> Result<(), ArrowError> {
        if self.state != ProtocolState::Established {
            return Err(ArrowError::other("cannot handle HUP message in the Handshake state"))
        }

        let hup = msg.body::<HupMessage>()
            .expect("HUP message expected");

        self.sessions.close(
            hup.session_id,
            hup.error_code);

        Ok(())
    }

    /// Process a given REDIRECT message.
    fn process_redirect_message(&mut self, msg: ControlMessage) -> Result<(), ArrowError> {
        if self.state != ProtocolState::Established {
            return Err(ArrowError::other("cannot handle REDIRECT message in the Handshake state"))
        }

        let msg = msg.body::<RedirectMessage>()
            .expect("REDIRECT message expected");

        self.redirect = Some(msg.target.clone());

        Ok(())
    }

    /// Process a given GET_STATUS message.
    fn process_get_status_message(&mut self, msg: ControlMessage) -> Result<(), ArrowError> {
        if self.state != ProtocolState::Established {
            return Err(ArrowError::other("cannot handle GET_STATUS message in the Handshake state"))
        }

        let header = msg.header();

        let mut status_flags = 0;

        // TODO: get application context
        /*if self.app_context.is_scanning() {
            status_flags |= STATUS_FLAG_SCAN;
        }*/

        log_debug!(self.logger, "sending a STATUS message...");

        let msg = self.cmsg_factory.status(
            header.msg_id,
            status_flags,
            self.sessions.len() as u32);

        self.send_control_message(msg);

        Ok(())
    }

    /// Process a given GET_SCAN_REPORT message.
    fn process_get_scan_report_message(&mut self, msg: ControlMessage) -> Result<(), ArrowError> {
        if self.state != ProtocolState::Established {
            return Err(ArrowError::other("cannot handle GET_SCAN_REPORT message in the Handshake state"))
        }

        let header = msg.header();

        // TODO: get scan report from application context
        let report = ScanReport::new();

        log_debug!(self.logger, "sending a SCAN_REPORT message...");

        let msg = self.cmsg_factory.scan_report(
            header.msg_id,
            report);

        self.send_control_message(msg);

        Ok(())
    }

    /// Send a given command using the underlaying command channel.
    fn process_command(&mut self, cmd: Command) -> Result<(), ArrowError> {
        if self.state != ProtocolState::Established {
            return Err(ArrowError::other(format!("cannot handle the {:?} command in the Handshake state", cmd)))
        }

        if let Err(cmd) = self.cmd_sender.send(cmd) {
            log_warn!(self.logger, "unable to process command {:?}", cmd);
        }

        Ok(())
    }

    /// Process a given service request message.
    fn process_service_request_message(&mut self, msg: ArrowMessage) -> Result<(), ArrowError> {
        if self.state != ProtocolState::Established {
            return Err(ArrowError::other("cannot handle service requests in the Handshake state"))
        }

        self.sessions.send(msg);

        Ok(())
    }
}

impl<L, S> Sink for ArrowClientContext<L, S>
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

impl<L, S> Stream for ArrowClientContext<L, S>
    where L: Logger,
          S: Sender {
    type Item  = ArrowMessage;
    type Error = ArrowError;

    fn poll(&mut self) -> Poll<Option<ArrowMessage>, ArrowError> {
        if self.ack_timeout() {
            return Err(ArrowError::connection_error("Arrow Service connection timeout"))
        } else if self.is_closed() {
            return Ok(Async::Ready(None))
        } else if let Some(msg) = self.messages.pop_front() {
            return Ok(Async::Ready(Some(msg)))
        } else if let Async::Ready(msg) = try!(self.sessions.poll()) {
            if msg.is_none() {
                panic!("session manager returned end of stream")
            } else {
                return Ok(Async::Ready(msg))
            }
        }

        self.task = Some(task::park());

        Ok(Async::NotReady)
    }
}

struct ArrowClient<L, S> {
    context: Rc<RefCell<ArrowClientContext<L, S>>>,
}

impl<L, S> ArrowClient<L, S>
    where L: 'static + Logger + Clone,
          S: 'static + Sender {
    /// Create a new instance of Arrow Client.
    fn new<T>(
        mut logger: L,
        cmd_sender: S,
        svc_table: T,
        tc_handle: TokioCoreHandle) -> ArrowClient<L, S>
        where T: 'static + ServiceTable {
        let context = ArrowClientContext::new(
            logger.clone(),
            cmd_sender,
            svc_table,
            tc_handle.clone());

        let context = Rc::new(RefCell::new(context));

        let event_handler = context.clone();

        let events = Timer::default()
            .interval(Duration::from_millis(1000))
            .map_err(|err| ArrowError::from(err))
            .for_each(move |_| {
                event_handler.borrow_mut()
                    .time_event()
            })
            .then(move |res| {
                if let Err(err) = res {
                    log_warn!(logger, "time event error: {}", err);
                }

                Ok(())
            });

        tc_handle.spawn(events);

        ArrowClient {
            context: context,
        }
    }
}

impl<L, S> ArrowClient<L, S>
    where L: Logger,
          S: Sender {
    /// Get redirect address (if any).
    fn get_redirect(&self) -> Option<String> {
        self.context.borrow()
            .get_redirect()
    }
}

impl<L, S> Sink for ArrowClient<L, S>
    where L: Logger,
          S: Sender {
    type SinkItem  = ArrowMessage;
    type SinkError = ArrowError;

    fn start_send(&mut self, msg: ArrowMessage) -> StartSend<ArrowMessage, ArrowError> {
        self.context.borrow_mut()
            .start_send(msg)
    }

    fn poll_complete(&mut self) -> Poll<(), ArrowError> {
        self.context.borrow_mut()
            .poll_complete()
    }
}

impl<L, S> Stream for ArrowClient<L, S>
    where L: Logger,
          S: Sender {
    type Item  = ArrowMessage;
    type Error = ArrowError;

    fn poll(&mut self) -> Poll<Option<ArrowMessage>, ArrowError> {
        self.context.borrow_mut()
            .poll()
    }
}

/// Connect Arrow Client to a given address and return either a redirect address or an error.
pub fn connect<L, S, T>(
    logger: L,
    cmd_sender: S,
    svc_table: T,
    addr: &str) -> Result<String, ArrowError>
    where L: 'static + Logger + Clone,
          S: 'static + Sender,
          T: 'static + ServiceTable {
    let mut core = TokioCore::new()?;

    let addr = addr.to_socket_addrs()
        .map_err(|err| ArrowError::connection_error(err))?
        .next()
        .ok_or(ArrowError::connection_error("unable to resolve a given address"))?;

    let aclient = ArrowClient::new(
        logger,
        cmd_sender,
        svc_table,
        core.handle());

    let client = TcpStream::connect(&addr, &core.handle())
        .map_err(|err| ArrowError::connection_error(err))
        .and_then(|stream| {
            let framed = stream.framed(ArrowCodec);
            let (sink, stream) = framed.split();

            let messages = stream.pipe(aclient);

            sink.send_all(messages)
                .and_then(|(_, pipe)| {
                    let (_, _, context) = pipe.unpipe();
                    let redirect = context.get_redirect()
                        .expect("connection closed, redirect expected");

                    Ok(redirect)
                })
        });

    core.run(client)
}
