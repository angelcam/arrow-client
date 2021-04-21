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

mod error;
mod proto;
mod session;

use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::sink::SinkExt;
use futures::stream::{Stream, StreamExt};
use futures::task::{Context, Poll, Waker};

use tokio_util::codec::Decoder;

use crate::cmd_handler::{Command, CommandChannel};
use crate::context::ApplicationContext;
use crate::net::arrow::proto::codec::{ArrowCodec, FromBytes};
use crate::net::arrow::proto::msg::control::ControlMessageFactory;
use crate::net::arrow::proto::msg::control::{
    AckMessage, ControlMessage, ControlMessageType, HupMessage, RedirectMessage,
    SimpleServiceTable, EC_INTERNAL_SERVER_ERROR, EC_NO_ERROR, EC_UNAUTHORIZED,
    EC_UNSUPPORTED_PROTOCOL_VERSION, STATUS_FLAG_SCAN,
};
use crate::net::arrow::proto::msg::ArrowMessage;
use crate::net::arrow::session::SessionManager;
use crate::net::raw::ether::MacAddr;
use crate::svc_table::SharedServiceTableRef;
use crate::utils::logger::{BoxLogger, Logger};

pub use self::error::{ArrowError, ErrorKind};

const ACK_TIMEOUT: Duration = Duration::from_secs(20);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(20);
const PING_PERIOD: Duration = Duration::from_secs(60);
const UPDATE_CHECK_PERIOD: Duration = Duration::from_secs(5);

/// Arrow Protocol states.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum ProtocolState {
    Handshake,
    Established,
}

/// Helper struct for expected ACK messages.
struct ExpectedAck {
    timestamp: Instant,
    message_id: u16,
}

impl ExpectedAck {
    /// Create a new ACK message expectation.
    fn new(message_id: u16) -> Self {
        Self {
            timestamp: Instant::now(),
            message_id,
        }
    }

    /// Check if it's too late for the ACK.
    fn timeout(&self) -> bool {
        self.timestamp.elapsed() >= ACK_TIMEOUT
    }
}

/// Arrow Client implementation.
struct ArrowClientContext {
    logger: BoxLogger,
    app_context: ApplicationContext,
    cmd_channel: CommandChannel,
    svc_table: SharedServiceTableRef,
    cmsg_factory: ControlMessageFactory,
    sessions: SessionManager,
    messages: VecDeque<ArrowMessage>,
    expected_acks: VecDeque<ExpectedAck>,
    state: ProtocolState,
    task: Option<Waker>,
    redirect: Option<String>,
    closed: bool,
    last_ping: Instant,
    last_update_chck: Instant,
    last_stable_ver: usize,
}

impl ArrowClientContext {
    /// Create a new Arrow Client.
    fn new(app_context: ApplicationContext, cmd_channel: CommandChannel) -> Self {
        let logger = app_context.get_logger();
        let svc_table = app_context.get_service_table();

        let mac = app_context.get_arrow_mac_address();
        let uuid = app_context.get_arrow_uuid();
        let passwd = app_context.get_arrow_password();

        let cmsg_factory = ControlMessageFactory::new();
        let session_manager = SessionManager::new(app_context.clone(), cmsg_factory.clone());

        let now = Instant::now();

        let mut client = Self {
            logger,
            app_context,
            cmd_channel,
            svc_table,
            cmsg_factory,
            sessions: session_manager,
            messages: VecDeque::new(),
            expected_acks: VecDeque::new(),
            state: ProtocolState::Handshake,
            task: None,
            redirect: None,
            closed: false,
            last_ping: now,
            last_update_chck: now,
            last_stable_ver: 0,
        };

        client.send_register_message(mac, *uuid.as_bytes(), *passwd.as_bytes());

        client
    }

    /// Get redirect address (if any).
    fn get_redirect(&self) -> Option<String> {
        self.redirect.as_ref().cloned()
    }

    /// Check if the client has been closed.
    fn is_closed(&self) -> bool {
        self.closed || self.redirect.is_some()
    }

    /// Check if there is an ACK timeout.
    fn ack_timeout(&self) -> bool {
        match self.expected_acks.front() {
            Some(expected_ack) => expected_ack.timeout(),
            None => false,
        }
    }

    /// Trigger all periodical tasks.
    fn time_event(&mut self) {
        if self.state == ProtocolState::Established {
            if self.last_ping.elapsed() >= PING_PERIOD {
                self.send_ping_message();
            }

            if self.last_update_chck.elapsed() >= UPDATE_CHECK_PERIOD {
                self.check_for_updates();
            }

            // notify the task consuming Arrow Messages about an ACK timeout
            if self.ack_timeout() {
                if let Some(task) = self.task.take() {
                    task.wake();
                }
            }
        }
    }

    /// Check if the service table has been updated.
    fn check_for_updates(&mut self) {
        if self.last_stable_ver != self.svc_table.version() {
            self.send_update_message();
        }

        self.last_update_chck = Instant::now();
    }

    /// Insert a given Control Protocol message into the output message queue.
    fn send_control_message(&mut self, msg: ControlMessage) {
        self.messages.push_back(ArrowMessage::from(msg));

        // notify the task consuming Arrow Messages about a new message
        if let Some(task) = self.task.take() {
            task.wake();
        }
    }

    /// Insert a given Control Protocol message into the output message queue
    /// and register an expected ACK.
    fn send_unconfirmed_control_message(&mut self, msg: ControlMessage) {
        let header = msg.header();

        self.expected_acks
            .push_back(ExpectedAck::new(header.msg_id));

        self.send_control_message(msg);
    }

    /// Send REGISTER message.
    fn send_register_message(&mut self, mac: MacAddr, uuid: [u8; 16], password: [u8; 16]) {
        log_debug!(self.logger, "sending REGISTER request...");

        let svc_table = SimpleServiceTable::from(self.svc_table.visible());

        let msg = self.cmsg_factory.register(mac, uuid, password, svc_table);

        self.last_stable_ver = self.svc_table.version();

        self.send_unconfirmed_control_message(msg);
    }

    /// Send UPDATE message.
    fn send_update_message(&mut self) {
        log_debug!(self.logger, "sending an UPDATE message...");

        let svc_table = SimpleServiceTable::from(self.svc_table.visible());

        let msg = self.cmsg_factory.update(svc_table);

        self.last_stable_ver = self.svc_table.version();

        self.send_control_message(msg);
    }

    /// Send PING message.
    fn send_ping_message(&mut self) {
        log_debug!(self.logger, "sending a PING message...");

        let msg = self.cmsg_factory.ping();

        self.send_unconfirmed_control_message(msg);

        self.last_ping = Instant::now();
    }

    /// Process a given Arrow Message.
    fn process_arrow_message(&mut self, msg: ArrowMessage) -> Result<(), ArrowError> {
        // ignore the message if the client has been closed
        if self.is_closed() {
            return Ok(());
        }

        let header = msg.header();

        if header.service == 0 {
            self.process_control_protocol_message(msg)?;
        } else {
            self.process_service_request_message(msg)?;
        }

        Ok(())
    }

    /// Process a given Control Protocol message.
    fn process_control_protocol_message(&mut self, msg: ArrowMessage) -> Result<(), ArrowError> {
        let msg = ControlMessage::from_bytes(msg.payload())?
            .expect("unable to decode an Arrow Control Protocol message");

        let header = msg.header();

        log_debug!(
            self.logger,
            "received control message: {:?}",
            header.message_type()
        );

        match header.message_type() {
            ControlMessageType::ACK => self.process_ack_message(msg),
            ControlMessageType::PING => self.process_ping_message(msg),
            ControlMessageType::HUP => self.process_hup_message(msg),
            ControlMessageType::REDIRECT => self.process_redirect_message(msg),
            ControlMessageType::GET_STATUS => self.process_get_status_message(msg),
            ControlMessageType::GET_SCAN_REPORT => self.process_get_scan_report_message(msg),
            ControlMessageType::RESET_SVC_TABLE => self.process_command(Command::ResetServiceTable),
            ControlMessageType::SCAN_NETWORK => self.process_command(Command::ScanNetwork),
            ControlMessageType::UNKNOWN => {
                Err(ArrowError::other("unknow control message received"))
            }
            mt => Err(ArrowError::other(format!(
                "unexpected control message received: {:?}",
                mt
            ))),
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
        let ack = msg.body::<AckMessage>().expect("ACK message expected");

        if ack.err == EC_NO_ERROR {
            // switch the protocol state into normal operation
            self.state = ProtocolState::Established;

            // report a fake redirect in case of the diagnostic mode
            if self.app_context.get_diagnostic_mode() {
                self.redirect = Some(String::new());
            }

            Ok(())
        } else if ack.err == EC_UNAUTHORIZED {
            Err(ArrowError::unauthorized(
                "Arrow REGISTER failed (unauthorized)",
            ))
        } else if ack.err == EC_UNSUPPORTED_PROTOCOL_VERSION {
            Err(ArrowError::unsupported_protocol_version(
                "Arrow REGISTER failed (unsupported version of the Arrow Protocol)",
            ))
        } else if ack.err == EC_INTERNAL_SERVER_ERROR {
            Err(ArrowError::arrow_server_error(
                "Arrow REGISTER failed (internal server error)",
            ))
        } else {
            Err(ArrowError::other("Arrow REGISTER failed (unknown error)"))
        }
    }

    /// Process a given PING message.
    fn process_ping_message(&mut self, msg: ControlMessage) -> Result<(), ArrowError> {
        if self.state != ProtocolState::Established {
            return Err(ArrowError::other(
                "cannot handle PING message in the Handshake state",
            ));
        }

        let header = msg.header();

        log_debug!(self.logger, "sending an ACK message...");

        let ack = self.cmsg_factory.ack(header.msg_id, 0x00);

        self.send_control_message(ack);

        Ok(())
    }

    /// Process a given HUP message.
    fn process_hup_message(&mut self, msg: ControlMessage) -> Result<(), ArrowError> {
        if self.state != ProtocolState::Established {
            return Err(ArrowError::other(
                "cannot handle HUP message in the Handshake state",
            ));
        }

        let hup = msg.body::<HupMessage>().expect("HUP message expected");

        self.sessions.close(hup.session_id, hup.error_code);

        Ok(())
    }

    /// Process a given REDIRECT message.
    fn process_redirect_message(&mut self, msg: ControlMessage) -> Result<(), ArrowError> {
        if self.state != ProtocolState::Established {
            return Err(ArrowError::other(
                "cannot handle REDIRECT message in the Handshake state",
            ));
        }

        let msg = msg
            .body::<RedirectMessage>()
            .expect("REDIRECT message expected");

        self.redirect = Some(msg.target.clone());

        // notify the task consuming Arrow Messages about the redirect
        if let Some(task) = self.task.take() {
            task.wake();
        }

        Ok(())
    }

    /// Process a given GET_STATUS message.
    fn process_get_status_message(&mut self, msg: ControlMessage) -> Result<(), ArrowError> {
        if self.state != ProtocolState::Established {
            return Err(ArrowError::other(
                "cannot handle GET_STATUS message in the Handshake state",
            ));
        }

        let header = msg.header();

        let mut status_flags = 0;

        if self.app_context.is_scanning() {
            status_flags |= STATUS_FLAG_SCAN;
        }

        log_debug!(self.logger, "sending a STATUS message...");

        let msg = self
            .cmsg_factory
            .status(header.msg_id, status_flags, self.sessions.len() as u32);

        self.send_control_message(msg);

        Ok(())
    }

    /// Process a given GET_SCAN_REPORT message.
    fn process_get_scan_report_message(&mut self, msg: ControlMessage) -> Result<(), ArrowError> {
        if self.state != ProtocolState::Established {
            return Err(ArrowError::other(
                "cannot handle GET_SCAN_REPORT message in the Handshake state",
            ));
        }

        let header = msg.header();

        log_debug!(self.logger, "sending a SCAN_REPORT message...");

        let scan_result = self.app_context.get_scan_result();
        let svc_table = self.app_context.get_service_table();

        let msg = self
            .cmsg_factory
            .scan_report(header.msg_id, scan_result, &svc_table);

        self.send_control_message(msg);

        Ok(())
    }

    /// Send a given command using the underlaying command channel.
    fn process_command(&mut self, cmd: Command) -> Result<(), ArrowError> {
        if self.state != ProtocolState::Established {
            return Err(ArrowError::other(format!(
                "cannot handle the {:?} command in the Handshake state",
                cmd
            )));
        }

        self.cmd_channel.send(cmd);

        Ok(())
    }

    /// Process a given service request message.
    fn process_service_request_message(&mut self, msg: ArrowMessage) -> Result<(), ArrowError> {
        if self.state != ProtocolState::Established {
            return Err(ArrowError::other(
                "cannot handle service requests in the Handshake state",
            ));
        }

        self.sessions.send(msg);

        Ok(())
    }
}

impl Stream for ArrowClientContext {
    type Item = Result<ArrowMessage, ArrowError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        if self.ack_timeout() {
            return Poll::Ready(Some(Err(ArrowError::connection_error(
                "Arrow Service connection timeout",
            ))));
        } else if self.is_closed() {
            return Poll::Ready(None);
        } else if let Some(msg) = self.messages.pop_front() {
            return Poll::Ready(Some(Ok(msg)));
        }

        match self.sessions.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(msg))) => return Poll::Ready(Some(Ok(msg))),
            Poll::Ready(Some(Err(err))) => return Poll::Ready(Some(Err(err))),
            Poll::Ready(None) => panic!("session manager returned end of stream"),
            Poll::Pending => (),
        }

        self.task = Some(cx.waker().clone());

        Poll::Pending
    }
}

struct ArrowClient<S> {
    context: Arc<Mutex<ArrowClientContext>>,
    stream: S,
}

impl<S> ArrowClient<S> {
    /// Create a new instance of Arrow Client.
    fn new(app_context: ApplicationContext, cmd_channel: CommandChannel, stream: S) -> Self {
        let context = ArrowClientContext::new(app_context, cmd_channel);

        let context = Arc::new(Mutex::new(context));

        let event_handler = context.clone();

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;

                {
                    let mut context = event_handler.lock().unwrap();
                    if context.is_closed() {
                        break;
                    }
                    context.time_event();
                }
            }
        });

        Self { context, stream }
    }

    /// Get redirect address (if any).
    fn get_redirect(&self) -> Option<String> {
        self.context.lock().unwrap().get_redirect()
    }
}

impl<S> Drop for ArrowClient<S> {
    fn drop(&mut self) {
        let mut context = self.context.lock().unwrap();

        // we must mark the context as closed so that the interval task gets terminated even in
        // case of connection/communication error
        context.closed = true;
    }
}

impl<S> Stream for ArrowClient<S>
where
    S: Stream<Item = Result<ArrowMessage, ArrowError>> + Unpin,
{
    type Item = Result<ArrowMessage, ArrowError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let ctx = self.context.clone();

        let mut context = ctx.lock().unwrap();

        // try to feed the context at least once on every poll
        match self.stream.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(msg))) => context.process_arrow_message(msg)?,
            Poll::Ready(Some(Err(err))) => return Poll::Ready(Some(Err(err))),
            Poll::Ready(None) => context.closed = true,
            Poll::Pending => (),
        }

        loop {
            // try to poll the context...
            if let Poll::Ready(ready) = context.poll_next_unpin(cx) {
                return Poll::Ready(ready);
            }

            // ... if it's pending, try to feed it again
            match self.stream.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(msg))) => context.process_arrow_message(msg)?,
                Poll::Ready(Some(Err(err))) => return Poll::Ready(Some(Err(err))),
                Poll::Ready(None) => context.closed = true,
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Connect Arrow Client to a given address and return either a redirect address or an error.
pub async fn connect(
    app_context: ApplicationContext,
    cmd_channel: CommandChannel,
    addr: &str,
) -> Result<String, ArrowError> {
    let tls_connector = app_context
        .get_tls_connector()
        .map_err(|err| ArrowError::other(format!("unable to get TLS context: {}", err)))?;

    let stream = tokio::time::timeout(CONNECTION_TIMEOUT, tls_connector.connect(addr))
        .await
        .map_err(|_| {
            ArrowError::connection_error(format!(
                "unable to connect to remote Arrow Service {} (connection timeout)",
                addr
            ))
        })?
        .map_err(|err| {
            ArrowError::connection_error(format!(
                "unable to connect to remote Arrow Service {} ({})",
                addr, err
            ))
        })?;

    let framed = ArrowCodec.framed(stream);

    let (mut sink, stream) = framed.split();

    let mut arrow_client = ArrowClient::new(app_context, cmd_channel, stream);

    let send = sink.send_all(&mut arrow_client);

    send.await?;

    arrow_client
        .get_redirect()
        .ok_or_else(|| ArrowError::connection_error("connection to Arrow Service lost"))
}
