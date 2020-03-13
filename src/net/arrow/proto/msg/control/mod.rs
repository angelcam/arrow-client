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

mod ack;
mod hup;
mod redirect;
mod register;
mod scan_report;
mod status;
mod svc_table;
mod update;

use std::mem;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::BytesMut;

use crate::utils;

use crate::net::arrow::proto::codec::{Encode, FromBytes};
use crate::net::arrow::proto::error::DecodeError;
use crate::net::arrow::proto::msg::{ArrowMessageBody, MessageBody};
use crate::net::raw::ether::MacAddr;
use crate::scanner::ScanResult;
use crate::svc_table::ServiceTable;
use crate::utils::AsAny;

use self::register::RegisterMessage;
use self::scan_report::ScanReportMessage;
use self::status::StatusMessage;
use self::update::UpdateMessage;

pub use self::ack::AckMessage;
pub use self::hup::HupMessage;
pub use self::redirect::RedirectMessage;
pub use self::svc_table::SimpleServiceTable;

// status flags
pub use self::status::STATUS_FLAG_SCAN;

// error codes
pub const EC_NO_ERROR: u32 = 0x0000_0000;
pub const EC_UNSUPPORTED_PROTOCOL_VERSION: u32 = 0x0000_0001;
pub const EC_UNAUTHORIZED: u32 = 0x0000_0002;
pub const EC_CONNECTION_ERROR: u32 = 0x0000_0003;
pub const EC_INTERNAL_SERVER_ERROR: u32 = 0xffff_ffff;

// unused error codes
//pub const EC_UNSUPPORTED_METHOD:           u32 = 0x0000_0004;

// message type constants
const CMSG_ACK: u16 = 0x0000;
const CMSG_PING: u16 = 0x0001;
const CMSG_REGISTER: u16 = 0x0002;
const CMSG_REDIRECT: u16 = 0x0003;
const CMSG_UPDATE: u16 = 0x0004;
const CMSG_HUP: u16 = 0x0005;
const CMSG_RESET_SVC_TABLE: u16 = 0x0006;
const CMSG_SCAN_NETWORK: u16 = 0x0007;
const CMSG_GET_STATUS: u16 = 0x0008;
const CMSG_STATUS: u16 = 0x0009;
const CMSG_GET_SCAN_REPORT: u16 = 0x000a;
const CMSG_SCAN_REPORT: u16 = 0x000b;

/// Arrow Control Protocol message types.
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ControlMessageType {
    ACK,
    PING,
    REGISTER,
    REDIRECT,
    UPDATE,
    HUP,
    RESET_SVC_TABLE,
    SCAN_NETWORK,
    GET_STATUS,
    STATUS,
    UNKNOWN,
    GET_SCAN_REPORT,
    SCAN_REPORT,
}

impl ControlMessageType {
    fn code(self) -> u16 {
        match self {
            Self::ACK => CMSG_ACK,
            Self::PING => CMSG_PING,
            Self::REGISTER => CMSG_REGISTER,
            Self::REDIRECT => CMSG_REDIRECT,
            Self::UPDATE => CMSG_UPDATE,
            Self::HUP => CMSG_HUP,
            Self::RESET_SVC_TABLE => CMSG_RESET_SVC_TABLE,
            Self::SCAN_NETWORK => CMSG_SCAN_NETWORK,
            Self::GET_STATUS => CMSG_GET_STATUS,
            Self::STATUS => CMSG_STATUS,
            Self::GET_SCAN_REPORT => CMSG_GET_SCAN_REPORT,
            Self::SCAN_REPORT => CMSG_SCAN_REPORT,
            Self::UNKNOWN => panic!("UNKNOWN Control Protocol message type has no code"),
        }
    }
}

/// Arrow Control Protocol message header.
#[derive(Debug, Copy, Clone)]
#[repr(packed)]
pub struct ControlMessageHeader {
    /// Message ID.
    pub msg_id: u16,
    /// Message type.
    msg_type: u16,
}

impl ControlMessageHeader {
    /// Create a new Control Protocol message header.
    fn new(msg_id: u16, msg_type: u16) -> Self {
        Self { msg_id, msg_type }
    }

    /// Get message type.
    pub fn message_type(self) -> ControlMessageType {
        match self.msg_type {
            CMSG_ACK => ControlMessageType::ACK,
            CMSG_PING => ControlMessageType::PING,
            CMSG_REGISTER => ControlMessageType::REGISTER,
            CMSG_REDIRECT => ControlMessageType::REDIRECT,
            CMSG_UPDATE => ControlMessageType::UPDATE,
            CMSG_HUP => ControlMessageType::HUP,
            CMSG_RESET_SVC_TABLE => ControlMessageType::RESET_SVC_TABLE,
            CMSG_SCAN_NETWORK => ControlMessageType::SCAN_NETWORK,
            CMSG_GET_STATUS => ControlMessageType::GET_STATUS,
            CMSG_STATUS => ControlMessageType::STATUS,
            CMSG_GET_SCAN_REPORT => ControlMessageType::GET_SCAN_REPORT,
            CMSG_SCAN_REPORT => ControlMessageType::SCAN_REPORT,
            _ => ControlMessageType::UNKNOWN,
        }
    }
}

impl Encode for ControlMessageHeader {
    fn encode(&self, buf: &mut BytesMut) {
        let be_header = Self {
            msg_id: self.msg_id.to_be(),
            msg_type: self.msg_type.to_be(),
        };

        buf.extend_from_slice(utils::as_bytes(&be_header))
    }
}

impl FromBytes for ControlMessageHeader {
    fn from_bytes(bytes: &[u8]) -> Result<Option<Self>, DecodeError> {
        assert_eq!(bytes.len(), mem::size_of::<Self>());

        let ptr = bytes.as_ptr() as *const Self;
        let header = unsafe { &*ptr };

        let header = Self {
            msg_id: u16::from_be(header.msg_id),
            msg_type: u16::from_be(header.msg_type),
        };

        Ok(Some(header))
    }
}

/// Common trait for Arrow Control Protocol message body implementations.
pub trait ControlMessageBody: MessageBody + AsAny + Send {}

/// Dummy type representing empty payload.
pub struct EmptyMessage;

impl Encode for EmptyMessage {
    fn encode(&self, _: &mut BytesMut) {}
}

impl MessageBody for EmptyMessage {
    fn len(&self) -> usize {
        0
    }
}

impl ControlMessageBody for EmptyMessage {}

/// Arrow Control Protocol message.
pub struct ControlMessage {
    /// Message header.
    header: ControlMessageHeader,
    /// Message body.
    body: Box<dyn ControlMessageBody>,
}

impl ControlMessage {
    /// Create a new ACK Control Protocol message.
    pub fn ack(msg_id: u16, err: u32) -> Self {
        Self::new(msg_id, ControlMessageType::ACK, AckMessage::new(err))
    }

    /// Create a new HUP Control Protocol message.
    pub fn hup(msg_id: u16, session_id: u32, error_code: u32) -> Self {
        Self::new(
            msg_id,
            ControlMessageType::HUP,
            HupMessage::new(session_id, error_code),
        )
    }

    /// Create a new STATUS Control Protocol message.
    pub fn status(msg_id: u16, request_id: u16, status_flags: u32, active_sessions: u32) -> Self {
        Self::new(
            msg_id,
            ControlMessageType::STATUS,
            StatusMessage::new(request_id, status_flags, active_sessions),
        )
    }

    /// Create a new SCAN_REPORT Control Protocol message.
    pub fn scan_report<T>(
        msg_id: u16,
        request_id: u16,
        scan_result: ScanResult,
        svc_table: &T,
    ) -> Self
    where
        T: ServiceTable,
    {
        Self::new(
            msg_id,
            ControlMessageType::SCAN_REPORT,
            ScanReportMessage::new(request_id, scan_result, svc_table),
        )
    }

    /// Create a new PING Control Protocol message.
    pub fn ping(msg_id: u16) -> Self {
        Self::new(msg_id, ControlMessageType::PING, EmptyMessage)
    }

    /// Create a new REGISTER Control Protocol message.
    pub fn register(
        msg_id: u16,
        mac: MacAddr,
        uuid: [u8; 16],
        password: [u8; 16],
        svc_table: SimpleServiceTable,
    ) -> Self {
        Self::new(
            msg_id,
            ControlMessageType::REGISTER,
            RegisterMessage::new(mac, uuid, password, svc_table),
        )
    }

    /// Create a new UPDATE Control Protocol message.
    pub fn update(msg_id: u16, svc_table: SimpleServiceTable) -> Self {
        Self::new(
            msg_id,
            ControlMessageType::UPDATE,
            UpdateMessage::new(svc_table),
        )
    }

    /// Create a new Control Protocol message.
    fn new<B>(msg_id: u16, msg_type: ControlMessageType, body: B) -> Self
    where
        B: ControlMessageBody + 'static,
    {
        Self {
            header: ControlMessageHeader::new(msg_id, msg_type.code()),
            body: Box::new(body),
        }
    }

    /// Get reference to the message header.
    pub fn header(&self) -> ControlMessageHeader {
        self.header
    }

    /// Get reference to the message body or None if the type of the message body does not match
    /// to the expected one.
    pub fn body<T: ControlMessageBody + 'static>(&self) -> Option<&T> {
        self.body.as_ref().as_any().downcast_ref()
    }

    /// Decode message body from given data according to a given message type.
    fn decode_body(
        mtype: ControlMessageType,
        bytes: &[u8],
    ) -> Result<Box<dyn ControlMessageBody>, DecodeError> {
        match mtype {
            ControlMessageType::ACK => Self::decode_ack_message(bytes),
            ControlMessageType::REDIRECT => Self::decode_redirect_message(bytes),
            ControlMessageType::HUP => Self::decode_hup_message(bytes),
            ControlMessageType::PING
            | ControlMessageType::RESET_SVC_TABLE
            | ControlMessageType::SCAN_NETWORK
            | ControlMessageType::GET_STATUS
            | ControlMessageType::GET_SCAN_REPORT => Self::decode_empty_message(bytes),
            ControlMessageType::UNKNOWN => Err(DecodeError::new(
                "unknown Arrow Control Protocol message type",
            )),
            _ => Err(DecodeError::new(
                "unexpected Arrow Control Protocol message type",
            )),
        }
    }

    /// Decode an ACK message from given data.
    fn decode_ack_message(bytes: &[u8]) -> Result<Box<dyn ControlMessageBody>, DecodeError> {
        if let Some(msg) = AckMessage::from_bytes(bytes)? {
            Ok(Box::new(msg))
        } else {
            panic!("unable to decode an Arrow Control Protocol ACK message")
        }
    }

    /// Decode a REDIRECT message from given data.
    fn decode_redirect_message(bytes: &[u8]) -> Result<Box<dyn ControlMessageBody>, DecodeError> {
        if let Some(msg) = RedirectMessage::from_bytes(bytes)? {
            Ok(Box::new(msg))
        } else {
            panic!("unable to decode an Arrow Control Protocol REGISTER message")
        }
    }

    /// Decode a HUP message from given data.
    fn decode_hup_message(bytes: &[u8]) -> Result<Box<dyn ControlMessageBody>, DecodeError> {
        if let Some(msg) = HupMessage::from_bytes(bytes)? {
            Ok(Box::new(msg))
        } else {
            panic!("unable to decode an Arrow Control Protocol HUP message")
        }
    }

    /// Decode an empty message from given data (i.e. just check there is no data).
    fn decode_empty_message(bytes: &[u8]) -> Result<Box<dyn ControlMessageBody>, DecodeError> {
        if bytes.is_empty() {
            Ok(Box::new(EmptyMessage))
        } else {
            Err(DecodeError::new("malformed Arrow Control Protocol message"))
        }
    }
}

impl Encode for ControlMessage {
    fn encode(&self, buf: &mut BytesMut) {
        self.header.encode(buf);
        self.body.encode(buf);
    }
}

impl MessageBody for ControlMessage {
    fn len(&self) -> usize {
        mem::size_of::<ControlMessageHeader>() + self.body.len()
    }
}

impl ArrowMessageBody for ControlMessage {}

impl FromBytes for ControlMessage {
    fn from_bytes(bytes: &[u8]) -> Result<Option<Self>, DecodeError> {
        let hsize = mem::size_of::<ControlMessageHeader>();

        if bytes.len() < hsize {
            return Err(DecodeError::new("malformed Arrow Control Protocol message"));
        }

        if let Some(header) = ControlMessageHeader::from_bytes(&bytes[..hsize])? {
            let body = Self::decode_body(header.message_type(), &bytes[hsize..])?;

            let msg = Self { header, body };

            Ok(Some(msg))
        } else {
            panic!("unable to decode an Arrow Control Protocol message")
        }
    }
}

/// Control Protocol message factory with shared message ID counter.
#[derive(Clone)]
pub struct ControlMessageFactory {
    counter: Arc<AtomicUsize>,
}

impl ControlMessageFactory {
    /// Create a new Control Protocol message factory.
    pub fn new() -> Self {
        Self {
            counter: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Get next message ID and increment the counter.
    fn next_id(&mut self) -> u16 {
        self.counter.fetch_add(1, Ordering::SeqCst) as u16
    }

    /// Create a new ACK message with a given error code.
    pub fn ack(&mut self, msg_id: u16, error_code: u32) -> ControlMessage {
        ControlMessage::ack(msg_id, error_code)
    }

    /// Create a new HUP message with a given session ID and error code.
    pub fn hup(&mut self, session_id: u32, error_code: u32) -> ControlMessage {
        ControlMessage::hup(self.next_id(), session_id, error_code)
    }

    /// Create a new STATUS message with a given request ID, flags and number
    /// of active sessions.
    pub fn status(
        &mut self,
        request_id: u16,
        status_flags: u32,
        active_sessions: u32,
    ) -> ControlMessage {
        ControlMessage::status(self.next_id(), request_id, status_flags, active_sessions)
    }

    /// Create a new SCAN_REPORT message for a given scan report.
    pub fn scan_report<T>(
        &mut self,
        request_id: u16,
        scan_result: ScanResult,
        svc_table: &T,
    ) -> ControlMessage
    where
        T: ServiceTable,
    {
        ControlMessage::scan_report(self.next_id(), request_id, scan_result, svc_table)
    }

    /// Create a new PING message.
    pub fn ping(&mut self) -> ControlMessage {
        ControlMessage::ping(self.next_id())
    }

    /// Create a new REGISTER message.
    pub fn register(
        &mut self,
        mac: MacAddr,
        uuid: [u8; 16],
        password: [u8; 16],
        svc_table: SimpleServiceTable,
    ) -> ControlMessage {
        ControlMessage::register(self.next_id(), mac, uuid, password, svc_table)
    }

    /// Create a new UPDATE message.
    pub fn update(&mut self, svc_table: SimpleServiceTable) -> ControlMessage {
        ControlMessage::update(self.next_id(), svc_table)
    }
}
