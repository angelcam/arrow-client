// Copyright 2015 click2stream, Inc.
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

//! Arrow Protocol implementation.

#[macro_use]
pub mod error;
pub mod protocol;
pub mod proto;

use std::cmp;
use std::mem;
use std::result;

use std::ffi::CStr;
use std::error::Error;
use std::collections::VecDeque;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::io::{Read, Write};

use utils;

use net::raw::ether::MacAddr;
use net::ssl::MioSslStream;
use net::utils::{Timeout, WriteBuffer, MioTcpStream,
    register_socket, reregister_socket, deregister_socket};

use utils::logger::Logger;
use utils::config::AppContext;
use utils::{Shared, Serialize};

use self::protocol::*;
use self::error::{Result, ArrowError};

use mio::{EventLoop, EventSet, Token, Handler};

use openssl::ssl::IntoSsl;

/// Commands that might be sent by the Arrow Client into a given mpsc queue.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Command {
    ResetServiceTable,
    ScanNetwork,
}

/// Common trait for various implementations of command senders.
pub trait Sender<C: Send> {
    /// Send a given command or return the command back if the send operation
    /// failed.
    fn send(&self, cmd: C) -> result::Result<(), C>;
}

/// External service session context.
///
/// This struct holds connection to an external service (e.g. RTSP) and
/// its I/O buffers.
struct SessionContext<L: Logger> {
    /// Logger.
    #[allow(dead_code)]
    logger:        L,
    /// Service ID.
    service_id:    u16,
    /// Session ID.
    session_id:    u32,
    /// TCP stream.
    stream:        MioTcpStream,
    /// Input buffer.
    input_buffer:  WriteBuffer,
    /// Output buffer.
    output_buffer: WriteBuffer,
    /// Read buffer.
    read_buffer:   Box<[u8]>,
    /// Write timeout.
    write_tout:    Timeout,
}

impl<L: Logger> SessionContext<L> {
    /// Create a new session context for a given session ID and service
    /// address.
    fn new<T: Handler>(
        logger:     L,
        service_id: u16,
        session_id: u32,
        addr: &SocketAddr,
        event_loop: &mut EventLoop<T>) -> Result<SessionContext<L>> {
        let stream = try_svc_io!(MioTcpStream::connect(addr));
        let token  = session2token(session_id);

        register_socket(Token(token), stream.get_ref(),
            true, true, event_loop);

        let res = SessionContext {
            logger:        logger,
            service_id:    service_id,
            session_id:    session_id,
            stream:        stream,
            input_buffer:  WriteBuffer::new(256 * 1024),
            output_buffer: WriteBuffer::new(0),
            read_buffer:   Box::new([0u8; 32768]),
            write_tout:    Timeout::new()
        };

        Ok(res)
    }

    /// Dispose resources held by this object.
    fn dispose<T: Handler>(&self, event_loop: &mut EventLoop<T>) {
        deregister_socket(self.stream.get_ref(), event_loop);
    }

    /// Enable/disable notifications for the underlaying socket.
    fn update_socket_events<T: Handler>(
        &mut self,
        event_loop: &mut EventLoop<T>) {
        let readable = !self.input_buffer.is_full();
        let writable = !self.output_buffer.is_empty();
        let token    = session2token(self.session_id);
        reregister_socket(
            Token(token),
            self.stream.get_ref(),
            readable, writable, event_loop);
    }

    /// Process a given set of socket events and return size of the input
    /// buffer or None in case the connection has been closed.
    fn socket_ready<T: Handler>(
        &mut self,
        event_loop: &mut EventLoop<T>,
        event_set: EventSet) -> Result<Option<usize>> {
        let read = try_arr!(self.check_read_event(event_loop, event_set));

        try_arr!(self.check_write_event(event_loop, event_set));

        if event_set.is_error() {
            let err = self.get_socket_error()
                .ok_or(ArrowError::other("socket error expected"));
            Err(try_arr!(err))
        } else if event_set.is_hup() && read == 0 {
            Ok(None)
        } else {
            Ok(Some(self.input_buffer.buffered()))
        }
    }

    /// Read a message if the underlaying socket is readable and the input
    /// buffer is not already full. Return the number of bytes read.
    fn check_read_event<T: Handler>(
        &mut self,
        event_loop: &mut EventLoop<T>,
        event_set: EventSet) -> Result<usize> {
        if event_set.is_readable() {
            if !self.input_buffer.is_full() || event_set.is_hup() {
                let buffer = &mut *self.read_buffer;
                let len    = try_svc_io!(self.stream.read(buffer));
                self.input_buffer.write_all(&buffer[..len])
                    .unwrap();

                //log_debug!(self.logger, "{} bytes read from session socket {:08x} (buffer size: {})", len, self.session_id, self.input_buffer.buffered());

                return Ok(len);
            } else {
                self.update_socket_events(event_loop);
            }
        }

        Ok(0)
    }

    /// Write data from the output buffer into the underlaying socket if the
    /// socket is writable.
    fn check_write_event<T: Handler>(
        &mut self,
        event_loop: &mut EventLoop<T>,
        event_set: EventSet) -> Result<()> {
        if event_set.is_writable() {
            if self.output_buffer.is_empty() {
                self.update_socket_events(event_loop);
                self.write_tout.clear();
            } else {
                let len = try_svc_io!(self.stream.write(
                    self.output_buffer.as_bytes()));

                if len > 0 {
                    //log_debug!(self.logger, "{} bytes written into session socket {:08x} (buffer size: {})", len, self.session_id, self.output_buffer.buffered());
                    self.output_buffer.drop(len);
                    self.write_tout.set(CONNECTION_TIMEOUT);
                }
            }
        }

        Ok(())
    }

    /// Get socket error.
    fn get_socket_error(&self) -> Option<ArrowError> {
        match self.stream.get_error() {
            Some(err) => Some(ArrowError::service_connection_error(err)),
            None      => None
        }
    }

    /// Check if there are some data in the input buffer.
    fn input_ready(&self) -> bool {
        !self.input_buffer.is_empty()
    }

    /// Get buffered input data.
    fn input_buffer(&self) -> &[u8] {
        self.input_buffer.as_bytes()
    }

    /// Drop a given number of bytes from the input buffer.
    fn drop_input_bytes<T: Handler>(
        &mut self,
        count: usize,
        event_loop: &mut EventLoop<T>) {
        let was_full = self.input_buffer.is_full();

        self.input_buffer.drop(count);

        if was_full && !self.input_buffer.is_full() {
            self.update_socket_events(event_loop);
        }
    }

    /// Send a given message.
    fn send_message<T: Handler>(
        &mut self,
        data: &[u8],
        event_loop: &mut EventLoop<T>) {
        let was_empty = self.output_buffer.is_empty();

        self.output_buffer.write_all(data)
            .unwrap();

        if was_empty {
            self.write_tout.set(CONNECTION_TIMEOUT);
            self.update_socket_events(event_loop);
        }
    }
}

/// Convert a given session ID into a token (socket) ID.
fn session2token(session_id: u32) -> usize {
    assert!(mem::size_of::<usize>() >= 4);
    (session_id as usize) | (1 << 24)
}

/// Convert a given token (socket) ID into a session ID.
fn token2session(token_id: usize) -> u32 {
    assert!(mem::size_of::<usize>() >= 4);
    let mask = ((1 as usize) << 24) - 1;
    assert!((token_id & !mask) == (1 << 24));
    (token_id & mask) as u32
}

/// Arrow Protocol states.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum ProtocolState {
    Handshake,
    Established
}

type SocketEventResult = Result<Option<String>>;

const UPDATE_CHECK_PERIOD:  u64 = 5000;
const TIMEOUT_CHECK_PERIOD: u64 = 1000;
const PING_PERIOD:          u64 = 60000;

const CONNECTION_TIMEOUT:   u64 = 20000;

/// Arrow client connection handler.
struct ConnectionHandler<L: Logger, Q: Sender<Command>> {
    /// Application logger.
    logger:        L,
    /// Shared application context.
    app_context:   Shared<AppContext>,
    /// Channel for sending Arrow Commands.
    cmd_sender:    Q,
    /// SSL/TLS connection to a remote Arrow Service.
    stream:        MioSslStream,
    /// Session contexts.
    sessions:      HashMap<u32, SessionContext<L>>,
    /// Session read queue.
    session_queue: VecDeque<u32>,
    /// Buffer for reading Arrow Protocol requests.
    read_buffer:   Box<[u8]>,
    /// Buffer for writing Arrow Protocol responses.
    write_buffer:  Box<[u8]>,
    /// Parser for requests received from Arrow Service.
    req_parser:    ArrowMessageParser,
    /// Output buffer for messages to be passed to Arrow Service.
    output_buffer: WriteBuffer,
    /// Arrow Client result returned after the connection shut down.
    result:        Option<Result<String>>,
    /// Protocol state.
    state:         ProtocolState,
    /// Version of the last sent service table.
    last_update:   Option<usize>,
    /// Write timeout.
    write_tout:    Timeout,
    /// ACK timeout.
    ack_tout:      Timeout,
    /// Current Control Message ID.
    msg_id:        u16,
    /// Expected ACKs.
    expected_acks: VecDeque<u16>,
}

impl<L: Logger + Clone, Q: Sender<Command>> ConnectionHandler<L, Q> {
    /// Create a new connection handler.
    fn new<S: IntoSsl>(
        logger: L,
        s: S,
        cmd_sender: Q,
        addr: &SocketAddr,
        arrow_mac: &MacAddr,
        app_context: Shared<AppContext>,
        event_loop: &mut EventLoop<Self>) -> Result<Self> {
        let stream = try_io!(MioSslStream::connect(s, addr, Token(0), event_loop));

        let mut res = ConnectionHandler {
            logger:        logger,
            app_context:   app_context,
            cmd_sender:    cmd_sender,
            stream:        stream,
            sessions:      HashMap::new(),
            session_queue: VecDeque::new(),
            read_buffer:   Box::new([0u8; 32768]),
            write_buffer:  Box::new([0u8; 16384]),
            req_parser:    ArrowMessageParser::new(),
            output_buffer: WriteBuffer::new(256 * 1024),
            result:        None,
            state:         ProtocolState::Handshake,
            last_update:   None,
            write_tout:    Timeout::new(),
            ack_tout:      Timeout::new(),
            msg_id:        0,
            expected_acks: VecDeque::new()
        };

        res.create_register_request(arrow_mac, event_loop);

        // start timeout checker:
        event_loop.timeout_ms(
                TimerEvent::TimeoutCheck(0),
                TIMEOUT_CHECK_PERIOD)
            .unwrap();

        Ok(res)
    }

    /// Get session context for a given session ID.
    fn get_session_context(
        &self,
        session_id: u32) -> Option<&SessionContext<L>> {
        self.sessions.get(&session_id)
    }

    /// Get session context for a given session ID.
    fn get_session_context_mut(
        &mut self,
        session_id: u32) -> Option<&mut SessionContext<L>> {
        self.sessions.get_mut(&session_id)
    }

    /// Create a new session context for a given service and session IDs.
    fn create_session_context(
        &mut self,
        service_id: u16,
        session_id: u32,
        event_loop: &mut EventLoop<Self>) -> Option<&mut SessionContext<L>> {
        if !self.sessions.contains_key(&session_id) {
            let app_context = self.app_context.lock()
                .unwrap();
            let config = &app_context.config;
            if let Some(svc) = config.get(service_id) {
                if let Some(addr) = svc.address() {
                    log_info!(self.logger, "connecting to remote service: {}, service ID: {:04x}, session ID: {:08x}", addr, service_id, session_id);
                    match SessionContext::new(self.logger.clone(),
                        service_id, session_id, addr, event_loop) {
                        Err(err) => log_warn!(self.logger, "unable to open connection to a remote service (address: {}, service ID: {:04x}, session ID: {:08x}): {}", addr, service_id, session_id, err.description()),
                        Ok(ctx)  => {
                            let token_id = session2token(session_id);
                            let tevent   = TimerEvent::TimeoutCheck(token_id);
                            self.sessions.insert(session_id, ctx);
                            self.session_queue.push_back(session_id);
                            event_loop.timeout_ms(tevent, TIMEOUT_CHECK_PERIOD)
                                .unwrap();
                        }
                    }
                } else {
                    log_warn!(self.logger, "requested service ID belongs to a Control Protocol service (session ID: {:08x})", session_id);
                }
            } else {
                log_warn!(self.logger, "non-existing service requested (service ID: {}, session ID: {:08x})", service_id, session_id);
            }
        }

        self.sessions.get_mut(&session_id)
    }

    /// Remove session context with a given session ID.
    fn remove_session_context(
        &mut self,
        session_id: u32,
        event_loop: &mut EventLoop<Self>) {
        if let Some(ctx) = self.sessions.remove(&session_id) {
            ctx.dispose(event_loop);
        }
    }

    /// Create a new REGISTER request.
    fn create_register_request(
        &mut self,
        arrow_mac: &MacAddr,
        event_loop: &mut EventLoop<Self>) {
        let control_msg = {
            let app_context = self.app_context.lock()
                .unwrap();
            let config    = &app_context.config;
            let svc_table = config.service_table()
                .clone();
            let msg    = RegisterMessage::new(
                config.uuid(),
                arrow_mac.octets(),
                config.password(),
                svc_table);
            let control_msg = control::create_register_message(self.msg_id,
                msg);
            self.last_update = Some(config.version());
            self.msg_id = self.msg_id.wrapping_add(1);
            control_msg
        };

        log_debug!(self.logger, "sending REGISTER request...");

        self.send_unconfirmed_control_message(control_msg, event_loop);
    }

    /// Send an update message (if needed) and schedule the next update event.
    fn send_update_message(
        &mut self,
        svc_table: ServiceTable,
        event_loop: &mut EventLoop<Self>) {
        let control_msg = control::create_update_message(self.msg_id,
            svc_table);

        self.msg_id = self.msg_id.wrapping_add(1);

        log_debug!(self.logger, "sending an UPDATE message...");

        self.send_control_message(control_msg, event_loop);
    }

    /// Send the PING message and schedule the next PING event.
    fn send_ping_message(&mut self, event_loop: &mut EventLoop<Self>) {
        let control_msg = control::create_ping_message(self.msg_id);

        self.msg_id = self.msg_id.wrapping_add(1);

        log_debug!(self.logger, "sending a PING message...");

        self.send_unconfirmed_control_message(control_msg, event_loop);
    }

    /// Send HUP message for a given session ID.
    fn send_hup_message(
        &mut self,
        session_id: u32,
        error_code: u32,
        event_loop: &mut EventLoop<Self>) {
        let control_msg = control::create_hup_message(self.msg_id,
            session_id, error_code);

        self.msg_id = self.msg_id.wrapping_add(1);

        log_debug!(self.logger, "sending a HUP message (session ID: {:08x}, error_code: {:08x})...", session_id, error_code);

        self.send_control_message(control_msg, event_loop);
    }

    /// Send status message for a given request ID.
    fn send_status(
        &mut self,
        request_id: u16,
        event_loop: &mut EventLoop<Self>) {
        let active_sessions  = self.sessions.len() as u32;
        let mut status_flags = 0;

        {
            let app_context = self.app_context.lock()
                .unwrap();

            if app_context.scanning {
                status_flags |= control::STATUS_FLAG_SCAN;
            }
        }

        let status_msg = StatusMessage::new(request_id,
            status_flags, active_sessions);
        let control_msg = control::create_status_message(self.msg_id,
            status_msg);

        self.msg_id = self.msg_id.wrapping_add(1);

        log_debug!(self.logger, "sending a STATUS message...");

        self.send_control_message(control_msg, event_loop);
    }

    /// Send scan report message for a given request ID.
    fn send_scan_report(
        &mut self,
        request_id: u16,
        event_loop: &mut EventLoop<Self>) {
        let scan_report;

        {
            let app_context = self.app_context.lock()
                .unwrap();

            scan_report = ScanReportMessage::new(
                request_id,
                app_context.scan_report.clone(),
                app_context.config.service_table()
                    .clone());
        }

        let control_msg = control::create_scan_report_message(self.msg_id,
            scan_report);

        self.msg_id += 1;

        log_debug!(self.logger, "sending a SCAN_REPORT message...");

        self.send_control_message(control_msg, event_loop);
    }

    /// Send ACK message with a given message id and error code.
    fn send_ack_message(
        &mut self,
        msg_id: u16,
        error_code: u32,
        event_loop: &mut EventLoop<Self>) {
        let control_msg = control::create_ack_message(msg_id, error_code);

        log_debug!(self.logger, "sending an ACK message...");

        self.send_control_message(control_msg, event_loop);
    }

    /// Send a given Control protocol message.
    fn send_control_message<B: ControlMessageBody>(
        &mut self,
        control_msg: ControlMessage<B>,
        event_loop: &mut EventLoop<Self>) {
        let arrow_msg = ArrowMessage::new(0, 0, control_msg);
        self.send_message(&arrow_msg, event_loop);
    }

    /// Send a given Control Protocol message which needs to be confirmed by
    // ACK.
    fn send_unconfirmed_control_message<B: ControlMessageBody>(
        &mut self,
        control_msg: ControlMessage<B>,
        event_loop: &mut EventLoop<Self>) {
        if self.expected_acks.is_empty() {
            self.ack_tout.set(CONNECTION_TIMEOUT);
        }

        let msg_id = control_msg.header()
            .msg_id;

        self.expected_acks.push_back(msg_id);

        self.send_control_message(control_msg, event_loop);
    }

    /// Send a given Arrow Message.
    fn send_message<B: ArrowMessageBody>(
        &mut self,
        arrow_msg: &ArrowMessage<B>,
        event_loop: &mut EventLoop<Self>) {
        if self.output_buffer.is_empty() {
            self.write_tout.set(CONNECTION_TIMEOUT);
        }

        arrow_msg.serialize(&mut self.output_buffer)
            .unwrap();

        self.stream.enable_socket_events(true, true, event_loop);
    }

    /// Check if the service table has been updated and send an UPDATE message
    /// if needed.
    fn check_update(&mut self, event_loop: &mut EventLoop<Self>) {
        let cur_version;
        let svc_table;

        {
            let app_context = self.app_context.lock()
                .unwrap();
            let config  = &app_context.config;
            cur_version = config.version();
            svc_table   = config.service_table()
                .clone();
        }

        let send_update = match self.last_update {
            Some(sent_version) => cur_version > sent_version,
            None => true
        };

        if send_update {
            self.send_update_message(svc_table, event_loop);
            self.last_update = Some(cur_version);
        }
    }

    /// Check if the service table has been updated and send an UPDATE message
    /// if needed.
    fn te_check_update(
        &mut self,
        event_loop: &mut EventLoop<Self>) -> Result<()> {
        self.check_update(event_loop);

        event_loop.timeout_ms(TimerEvent::Update, UPDATE_CHECK_PERIOD)
            .unwrap();

        Ok(())
    }

    /// Periodical connection check.
    fn te_check_connection(
        &mut self,
        event_loop: &mut EventLoop<Self>) -> Result<()> {
        self.send_ping_message(event_loop);

        event_loop.timeout_ms(TimerEvent::Ping, PING_PERIOD)
            .unwrap();

        Ok(())
    }

    /// Check connection timeout.
    fn te_check_timeout(
        &mut self,
        token: usize,
        event_loop: &mut EventLoop<Self>) -> Result<()> {
        match token {
            0 => self.check_arrow_timeout(event_loop),
            t => self.check_session_timeout(token2session(t), event_loop)
        }
    }

    /// Check connection timeout of the underlaying Arrow socket.
    fn check_arrow_timeout(
        &mut self,
        event_loop: &mut EventLoop<Self>) -> Result<()> {
        if !self.write_tout.check() || !self.ack_tout.check() {
            Err(ArrowError::connection_error("Arrow Service connection timeout"))
        } else {
            event_loop.timeout_ms(
                    TimerEvent::TimeoutCheck(0),
                    TIMEOUT_CHECK_PERIOD)
                .unwrap();

            Ok(())
        }
    }

    /// Check session communication timeout.
    fn check_session_timeout(
        &mut self,
        session_id: u32,
        event_loop: &mut EventLoop<Self>) -> Result<()> {
        let mut timeout = false;

        if let Some(ctx) = self.get_session_context(session_id) {
            timeout = !ctx.write_tout.check();
        }

        if timeout {
            log_warn!(self.logger, "session {:08x} connection timeout", session_id);
            self.send_hup_message(session_id, 0, event_loop);
            self.remove_session_context(session_id, event_loop);
        } else {
            event_loop.timeout_ms(
                    TimerEvent::TimeoutCheck(session2token(session_id)),
                    TIMEOUT_CHECK_PERIOD)
                .unwrap();
        }

        Ok(())
    }

    /// Process all notifications for the underlaying TLS socket.
    fn arrow_socket_ready(
        &mut self,
        event_loop: &mut EventLoop<Self>,
        event_set: EventSet) -> SocketEventResult {
        let res = try_arr!(self.check_arrow_read_event(event_loop, event_set));
        if res.is_some() {
            return Ok(res);
        }

        let res = try_arr!(self.check_arrow_write_event(event_loop, event_set));
        if res.is_some() {
            return Ok(res);
        }

        if event_set.is_error() {
            match self.stream.get_error() {
                Some(err) => Err(ArrowError::connection_error(err)),
                None      => Err(ArrowError::connection_error("unknown connection error"))
            }
        } else if event_set.is_hup() {
            Err(ArrowError::connection_error("connection to Arrow Service lost"))
        } else {
            Ok(None)
        }
    }

    /// Read a request/response chunk if the underlaying TLS socket is
    /// readable.
    fn check_arrow_read_event(
        &mut self,
        event_loop: &mut EventLoop<Self>,
        event_set: EventSet) -> SocketEventResult {
        if self.stream.can_read(event_set) {
            self.read_request(event_loop)
        } else {
            Ok(None)
        }
    }

    /// Write a request/response chunk if the underlaying TLS socket is
    /// writable.
    fn check_arrow_write_event(
        &mut self,
        event_loop: &mut EventLoop<Self>,
        event_set: EventSet) -> SocketEventResult {
        if self.stream.can_write(event_set) {
            self.send_response(event_loop)
        } else {
            Ok(None)
        }
    }

    /// Read request data from the underlaying TLS socket.
    fn read_request(
        &mut self,
        event_loop: &mut EventLoop<Self>) -> SocketEventResult {
        let mut consumed = 0;

        let len = try_io!(self.stream.read(&mut *self.read_buffer, event_loop));

        //log_debug!(self.logger, "{} bytes read from the Arrow socket", len);

        while consumed < len {
            consumed += try_arr!(self.req_parser.add(
                &self.read_buffer[consumed..len]));
            if self.req_parser.is_complete() {
                let redirect = try_arr!(self.process_request(event_loop));
                if redirect.is_some() {
                    return Ok(redirect);
                }
            }
        }

        Ok(None)
    }

    /// Parse the last complete request.
    ///
    /// # Panics
    /// If the last request has not been completed yet.
    fn process_request(
        &mut self,
        event_loop: &mut EventLoop<Self>) -> SocketEventResult {
        let service_id;
        let session_id;

        if let Some(header) = self.req_parser.header() {
            service_id = header.service;
            session_id = header.session;
        } else {
            panic!("incomplete message")
        }

        match service_id {
            0 => self.process_control_message(event_loop),
            _ => self.process_service_request(service_id, session_id,
                event_loop)
        }
    }

    /// Process a Control Protocol message.
    fn process_control_message(
        &mut self,
        event_loop: &mut EventLoop<Self>) -> SocketEventResult {
        let (header, body) = try_arr!(self.parse_control_message());

        log_debug!(self.logger, "received control message: {:?}", header.message_type());

        let res = match header.message_type() {
            ControlMessageType::ACK =>
                self.process_ack_message(header.msg_id, &body, event_loop),
            ControlMessageType::PING =>
                self.process_ping_message(header.msg_id, event_loop),
            ControlMessageType::REDIRECT =>
                self.process_redirect_message(&body),
            ControlMessageType::HUP =>
                self.process_hup_message(&body, event_loop),
            ControlMessageType::RESET_SVC_TABLE =>
                self.process_command(Command::ResetServiceTable),
            ControlMessageType::SCAN_NETWORK =>
                self.process_command(Command::ScanNetwork),
            ControlMessageType::GET_STATUS =>
                self.process_status_request(header.msg_id, event_loop),
            ControlMessageType::GET_SCAN_REPORT =>
                self.process_scan_report_request(header.msg_id, event_loop),
            mt => Err(ArrowError::other(format!("cannot handle Control Protocol message type: {:?}", mt)))
        };

        self.req_parser.clear();

        res
    }

    /// Parse a Control Protocol message from the underlaying Arrow Message
    /// parser.
    fn parse_control_message(&self) -> Result<(ControlMessageHeader, Vec<u8>)> {
        if let Some(body) = self.req_parser.body() {
            let mut parser = ControlMessageParser::new();
            try_arr!(parser.process(body));
            let header = parser.header();
            let body   = parser.body();
            if header.message_type() == ControlMessageType::UNKNOWN {
                Err(ArrowError::other("unknown Control Protocol message type"))
            } else {
                Ok((header.clone(), body.to_vec()))
            }
        } else {
            panic!("incomplete message");
        }
    }

    /// Process a Control Protocol ACK message.
    fn process_ack_message(
        &mut self,
        msg_id: u16,
        msg: &[u8],
        event_loop: &mut EventLoop<Self>) -> SocketEventResult {
        let expected_ack = self.expected_acks.pop_front();

        if self.expected_acks.is_empty() {
            self.ack_tout.clear();
        } else {
            self.ack_tout.set(CONNECTION_TIMEOUT);
        }

        if let Some(expected_ack) = expected_ack {
            if msg_id == expected_ack {
                if self.state == ProtocolState::Handshake {
                    self.process_handshake_ack(msg, event_loop)
                } else {
                    Ok(None)
                }
            } else {
                Err(ArrowError::other("unexpected ACK message ID"))
            }
        } else {
            Err(ArrowError::other("no ACK message expected"))
        }
    }

    /// Process ACK response for the REGISTER command.
    fn process_handshake_ack(
        &mut self,
        msg: &[u8],
        event_loop: &mut EventLoop<Self>) -> SocketEventResult {
        if self.state == ProtocolState::Handshake {
            let ack = try_arr!(control::parse_ack_message(msg));
            if ack == ACK_NO_ERROR {
                // switch the protocol state into normal operation
                self.state = ProtocolState::Established;

                // start sending update messages
                event_loop.timeout_ms(TimerEvent::Update, UPDATE_CHECK_PERIOD)
                    .unwrap();

                // start sending PING messages
                event_loop.timeout_ms(TimerEvent::Ping, PING_PERIOD)
                    .unwrap();

                let diagnostic_mode = self.app_context.lock()
                    .unwrap()
                    .diagnostic_mode;

                // report a fake redirect in case of the diagnostic mode
                if diagnostic_mode {
                    Ok(Some(String::new()))
                } else {
                    Ok(None)
                }
            } else if ack == ACK_UNAUTHORIZED {
                Err(ArrowError::unauthorized("Arrow REGISTER failed (unauthorized)"))
            } else if ack == ACK_UNSUPPORTED_PROTOCOL_VERSION {
                Err(ArrowError::unsupported_protocol_version("Arrow REGISTER failed (unsupported version of the Arrow Protocol)"))
            } else if ack == ACK_INTERNAL_SERVER_ERROR {
                Err(ArrowError::arrow_server_error("Arrow REGISTER failed (internal server error)"))
            } else {
                Err(ArrowError::other("Arrow REGISTER failed (unknown error)"))
            }
        } else {
            panic!("unexpected protocol state");
        }
    }

    /// Process a Control Protocol PING message.
    fn process_ping_message(
        &mut self,
        msg_id: u16,
        event_loop: &mut EventLoop<Self>) -> SocketEventResult {
        if self.state == ProtocolState::Established {
            self.send_ack_message(msg_id, 0, event_loop);
            Ok(None)
        } else {
            Err(ArrowError::other("cannot handle PING message in the Handshake state"))
        }
    }

    /// Process a Control Protocol REDIRECT message.
    fn process_redirect_message(&mut self, msg: &[u8]) -> SocketEventResult {
        if self.state == ProtocolState::Established {
            let ptr  = msg.as_ptr();
            let cstr = unsafe {
                CStr::from_ptr(ptr as *const _)
            };

            let addr = String::from_utf8_lossy(cstr.to_bytes());

            Ok(Some(addr.to_string()))
        } else {
            Err(ArrowError::other("cannot handle REDIRECT message in the Handshake state"))
        }
    }

    /// Process a Control Protocol HUP message.
    fn process_hup_message(
        &mut self,
        msg: &[u8],
        event_loop: &mut EventLoop<Self>) -> SocketEventResult {
        if self.state == ProtocolState::Established {
            let msg        = try_arr!(HupMessage::from_bytes(msg));
            let session_id = msg.session_id;
            // XXX: the HUP error code should be processed here
            log_info!(self.logger, "session {:08x} closed", session_id);
            self.remove_session_context(session_id, event_loop);
            Ok(None)
        } else {
            Err(ArrowError::other("cannot handle HUP message in the Handshake state"))
        }
    }

    /// Send command using the underlaying command channel.
    fn process_command(&mut self, cmd: Command) -> SocketEventResult {
        match self.cmd_sender.send(cmd) {
            Err(cmd) => log_warn!(self.logger, "unable to process command {:?}", cmd),
            _ => ()
        }

        Ok(None)
    }

    /// Process status request (GET_STATUS message) with a given ID.
    fn process_status_request(
        &mut self,
        msg_id: u16,
        event_loop: &mut EventLoop<Self>) -> SocketEventResult {
        self.send_status(msg_id, event_loop);
        Ok(None)
    }

    /// Process scan report request (GET_SCAN_REPORT message) with a given ID.
    fn process_scan_report_request(
        &mut self,
        msg_id: u16,
        event_loop: &mut EventLoop<Self>) -> SocketEventResult {
        let discovery;

        {
            let app_context = self.app_context.lock()
                .unwrap();

            discovery = app_context.discovery;
        }

        if discovery {
            self.send_scan_report(msg_id, event_loop);
        } else {
            self.send_ack_message(msg_id, ACK_UNSUPPORTED_METHOD, event_loop);
        }

        Ok(None)
    }

    /// Process request for a remote service.
    fn process_service_request(
        &mut self,
        service_id: u16,
        session_id: u32,
        event_loop: &mut EventLoop<Self>) -> SocketEventResult {
        if self.state == ProtocolState::Established {
            let request = match self.req_parser.body() {
                Some(body) => body.to_vec(),
                None => panic!("incomplete message")
            };

            self.req_parser.clear();

            let send_hup = match self.create_session_context(
                service_id, session_id, event_loop) {
                None      => true,
                Some(ctx) => {
                    ctx.send_message(&request, event_loop);
                    false
                }
            };

            if send_hup {
                self.send_hup_message(session_id, 1, event_loop);
            }

            Ok(None)
        } else {
            Err(ArrowError::other("cannot handle service requests in the Handshake state"))
        }
    }

    /// Fill the Arrow Protocol output buffer with data from session input
    /// buffers.
    fn fill_output_buffer(&mut self, event_loop: &mut EventLoop<Self>) {
        // using round robin alg. here in order to avoid session read
        // starvation
        let mut queue_size = self.session_queue.len();
        while queue_size > 0 && !self.output_buffer.is_full() {
            if let Some(session_id) = self.session_queue.pop_front() {
                if let Some(ctx) = self.sessions.get_mut(&session_id) {
                    // avoid sending empty packets
                    let len = if ctx.input_ready() {
                        let data = ctx.input_buffer();
                        let len  = cmp::min(32768, data.len());
                        let arrow_msg = ArrowMessage::new(
                            ctx.service_id, ctx.session_id,
                            &data[..len]);

                        if self.output_buffer.is_empty() {
                            self.write_tout.set(CONNECTION_TIMEOUT);
                        }

                        arrow_msg.serialize(&mut self.output_buffer)
                            .unwrap();

                        len
                    } else {
                        0
                    };

                    ctx.drop_input_bytes(len, event_loop);

                    self.session_queue.push_back(session_id);

                    //log_debug!(self.logger, "{} bytes moved from session {:08x} input buffer into the Arrow output buffer", len, session_id);
                }
            }

            queue_size -= 1;
        }
    }

    /// Send response data using the underlaying TLS socket.
    fn send_response(
        &mut self,
        event_loop: &mut EventLoop<Self>) -> SocketEventResult {
        self.fill_output_buffer(event_loop);

        if self.output_buffer.is_empty() {
            self.stream.enable_socket_events(true, false, event_loop);
            self.write_tout.clear();
        } else {
            let len = {
                let data   = self.output_buffer.as_bytes();
                let len    = cmp::min(data.len(), self.write_buffer.len());
                let buffer = &mut self.write_buffer[..len];
                utils::memcpy(buffer, &data[..len]);
                try_io!(self.stream.write(buffer, event_loop))
            };

            if len > 0 {
                //log_debug!(self.logger, "{} bytes written into the Arrow socket", len);
                self.write_tout.set(CONNECTION_TIMEOUT);
                self.output_buffer.drop(len);
            }
        }

        Ok(None)
    }

    /// Move all data from the session input buffer into the Arrow output
    /// buffer.
    fn flush_session(
        &mut self,
        session_id: u32,
        event_loop: &mut EventLoop<Self>) {
        if let Some(ctx) = self.sessions.get_mut(&session_id) {
            // avoid sending empty packets
            let len = if ctx.input_ready() {
                let data = ctx.input_buffer();
                let arrow_msg = ArrowMessage::new(
                    ctx.service_id, ctx.session_id,
                    data);

                if self.output_buffer.is_empty() {
                    self.write_tout.set(CONNECTION_TIMEOUT);
                }

                arrow_msg.serialize(&mut self.output_buffer)
                    .unwrap();

                data.len()
            } else {
                0
            };

            ctx.drop_input_bytes(len, event_loop);

            self.stream.enable_socket_events(true, true, event_loop);

            //log_debug!(self.logger, "{} bytes moved from session {:08x} input buffer into the Arrow output buffer", len, session_id);
        }
    }

    /// Process all notifications for a given remote session socket.
    fn session_socket_ready(
        &mut self,
        session_id: u32,
        event_loop: &mut EventLoop<Self>,
        event_set: EventSet) -> SocketEventResult {
        let res = match self.get_session_context_mut(session_id) {
            Some(ctx) => ctx.socket_ready(event_loop, event_set),
            None      => Ok(Some(0))
        };

        match res {
            Err(err) => {
                log_warn!(self.logger, "service connection error (session ID: {:08x}): {}", session_id, err.description());
                self.flush_session(session_id, event_loop);
                self.send_hup_message(session_id, 2, event_loop);
                self.remove_session_context(session_id, event_loop);
            },
            Ok(None) => {
                log_info!(self.logger, "service connection closed (session ID: {:08x})", session_id);
                self.flush_session(session_id, event_loop);
                self.send_hup_message(session_id, 0, event_loop);
                self.remove_session_context(session_id, event_loop);
            },
            Ok(Some(size)) if size > 0 => {
                self.stream.enable_socket_events(true, true, event_loop);
            },
            _ => ()
        }

        Ok(None)
    }
}

/// Types of epoll() timer events.
#[derive(Debug, Copy, Clone)]
enum TimerEvent {
    Update,
    Ping,
    TimeoutCheck(usize),
}

impl<L, Q> Handler for ConnectionHandler<L, Q>
    where L: Logger + Clone,
          Q: Sender<Command> {
    type Timeout = TimerEvent;
    type Message = ();

    /// Event loop handler method.
    fn ready(
        &mut self,
        event_loop: &mut EventLoop<Self>,
        token: Token,
        event_set: EventSet) {
        let res = match token {
            Token(0)  => self.arrow_socket_ready(event_loop, event_set),
            Token(id) => self.session_socket_ready(token2session(id),
                event_loop, event_set)
        };

        match res {
            Ok(None)           => (),
            Ok(Some(redirect)) => self.result = Some(Ok(redirect)),
            Err(err)           => self.result = Some(Err(err))
        }

        if self.result.is_some() {
            event_loop.shutdown();
        }
    }

    /// Timer handler method.
    fn timeout(&mut self, event_loop: &mut EventLoop<Self>, token: TimerEvent) {
        let res = match token {
            TimerEvent::Update => self.te_check_update(event_loop),
            TimerEvent::Ping   => self.te_check_connection(event_loop),
            TimerEvent::TimeoutCheck(token) =>
                self.te_check_timeout(token, event_loop)
        };

        match res {
            Err(err) => self.result = Some(Err(err)),
            _        => ()
        }

        if self.result.is_some() {
            event_loop.shutdown();
        }
    }
}

/// Arrow client.
pub struct ArrowClient<L: Logger + Clone, Q: Sender<Command>> {
    connection: ConnectionHandler<L, Q>,
    event_loop: EventLoop<ConnectionHandler<L, Q>>,
}

impl<L: Logger + Clone, Q: Sender<Command>> ArrowClient<L, Q> {
    /// Create a new Arrow client.
    pub fn new<S: IntoSsl>(
        logger: L,
        s: S,
        cmd_sender: Q,
        addr: &SocketAddr,
        arrow_mac: &MacAddr,
        app_context: Shared<AppContext>) -> Result<Self> {
        let mut event_loop    = try_other!(EventLoop::new());
        let connection        = try_arr!(ConnectionHandler::new(
            logger, s, cmd_sender,
            addr, arrow_mac, app_context,
            &mut event_loop));

        let res = ArrowClient {
            connection: connection,
            event_loop: event_loop
        };

        Ok(res)
    }

    /// Connect to the remote Arrow Service and start listening for incoming
    /// requests. Return error or redirect address in case the connection has
    /// been shut down.
    pub fn event_loop(&mut self) -> Result<String> {
        try_other!(self.event_loop.run(&mut self.connection));
        match self.connection.result {
            Some(ref res) => res.clone(),
            _             => panic!("result expected")
        }
    }
}
