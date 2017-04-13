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

pub mod ack;
pub mod hup;
pub mod redirect;
pub mod register;
pub mod scan_report;
pub mod status;
pub mod svc_table;
pub mod update;

use std::mem;
use std::str;

use bytes::BytesMut;

use utils;

use utils::AsAny;

use net::arrow::proto::codec::{FromBytes, Encode};
use net::arrow::proto::msg::{ArrowMessageBody, MessageBody};
use net::arrow::proto::error::DecodeError;

use self::status::StatusMessage;
use self::scan_report::ScanReportMessage;

pub use self::ack::AckMessage;
pub use self::hup::HupMessage;
pub use self::redirect::RedirectMessage;
pub use self::scan_report::ScanReport;
pub use self::svc_table::{
    BoxServiceTable,
    Service,
    ServiceTable,
    ServiceType,
    SimpleServiceTable,

    SVC_TYPE_CONTROL_PROTOCOL,
    SVC_TYPE_RTSP,
    SVC_TYPE_LOCKED_RTSP,
    SVC_TYPE_UNKNOWN_RTSP,
    SVC_TYPE_UNSUPPORTED_RTSP,
    SVC_TYPE_HTTP,
    SVC_TYPE_MJPEG,
    SVC_TYPE_LOCKED_MJPEG,
    SVC_TYPE_TCP,
};

// ACK codes
pub use self::ack::{
    ACK_NO_ERROR,
    ACK_UNSUPPORTED_PROTOCOL_VERSION,
    ACK_UNAUTHORIZED,
    ACK_CONNECTION_ERROR,
    ACK_UNSUPPORTED_METHOD,
    ACK_INTERNAL_SERVER_ERROR,
};

// message type constants
const CMSG_ACK:             u16 = 0x0000;
const CMSG_PING:            u16 = 0x0001;
const CMSG_REGISTER:        u16 = 0x0002;
const CMSG_REDIRECT:        u16 = 0x0003;
const CMSG_UPDATE:          u16 = 0x0004;
const CMSG_HUP:             u16 = 0x0005;
const CMSG_RESET_SVC_TABLE: u16 = 0x0006;
const CMSG_SCAN_NETWORK:    u16 = 0x0007;
const CMSG_GET_STATUS:      u16 = 0x0008;
const CMSG_STATUS:          u16 = 0x0009;
const CMSG_GET_SCAN_REPORT: u16 = 0x000a;
const CMSG_SCAN_REPORT:     u16 = 0x000b;

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
    fn code(&self) -> u16 {
        match *self {
            ControlMessageType::ACK             => CMSG_ACK,
            ControlMessageType::PING            => CMSG_PING,
            ControlMessageType::REGISTER        => CMSG_REGISTER,
            ControlMessageType::REDIRECT        => CMSG_REDIRECT,
            ControlMessageType::UPDATE          => CMSG_UPDATE,
            ControlMessageType::HUP             => CMSG_HUP,
            ControlMessageType::RESET_SVC_TABLE => CMSG_RESET_SVC_TABLE,
            ControlMessageType::SCAN_NETWORK    => CMSG_SCAN_NETWORK,
            ControlMessageType::GET_STATUS      => CMSG_GET_STATUS,
            ControlMessageType::STATUS          => CMSG_STATUS,
            ControlMessageType::GET_SCAN_REPORT => CMSG_GET_SCAN_REPORT,
            ControlMessageType::SCAN_REPORT     => CMSG_SCAN_REPORT,
            ControlMessageType::UNKNOWN         => panic!("UNKNOWN Control Protocol message type has no code"),
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
    msg_type:   u16,
}

impl ControlMessageHeader {
    /// Create a new Control Protocol message header.
    fn new(msg_id: u16, msg_type: u16) -> ControlMessageHeader {
        ControlMessageHeader {
            msg_id:   msg_id,
            msg_type: msg_type,
        }
    }

    /// Get message type.
    pub fn message_type(&self) -> ControlMessageType {
        match self.msg_type {
            CMSG_ACK             => ControlMessageType::ACK,
            CMSG_PING            => ControlMessageType::PING,
            CMSG_REGISTER        => ControlMessageType::REGISTER,
            CMSG_REDIRECT        => ControlMessageType::REDIRECT,
            CMSG_UPDATE          => ControlMessageType::UPDATE,
            CMSG_HUP             => ControlMessageType::HUP,
            CMSG_RESET_SVC_TABLE => ControlMessageType::RESET_SVC_TABLE,
            CMSG_SCAN_NETWORK    => ControlMessageType::SCAN_NETWORK,
            CMSG_GET_STATUS      => ControlMessageType::GET_STATUS,
            CMSG_STATUS          => ControlMessageType::STATUS,
            CMSG_GET_SCAN_REPORT => ControlMessageType::GET_SCAN_REPORT,
            CMSG_SCAN_REPORT     => ControlMessageType::SCAN_REPORT,
            _ => ControlMessageType::UNKNOWN
        }
    }
}

impl Encode for ControlMessageHeader {
    fn encode(&self, buf: &mut BytesMut) {
        let be_header = ControlMessageHeader {
            msg_id:   self.msg_id.to_be(),
            msg_type: self.msg_type.to_be()
        };

        buf.extend(utils::as_bytes(&be_header))
    }
}

impl FromBytes for ControlMessageHeader {
    fn from_bytes(bytes: &[u8]) -> Result<Option<ControlMessageHeader>, DecodeError> {
        assert_eq!(bytes.len(), mem::size_of::<ControlMessageHeader>());

        let ptr    = bytes.as_ptr() as *const ControlMessageHeader;
        let header = unsafe { &*ptr };

        let header = ControlMessageHeader {
            msg_id:   u16::from_be(header.msg_id),
            msg_type: u16::from_be(header.msg_type)
        };

        Ok(Some(header))
    }
}

/// Common trait for Arrow Control Protocol message body implementations.
pub trait ControlMessageBody : MessageBody + AsAny + Send {
}

/// Dummy type representing empty payload.
pub struct EmptyMessage;

impl Encode for EmptyMessage {
    fn encode(&self, _: &mut BytesMut) {
    }
}

impl MessageBody for EmptyMessage {
    fn len(&self) -> usize {
        0
    }
}

impl ControlMessageBody for EmptyMessage {
}

/// Arrow Control Protocol message.
pub struct ControlMessage {
    /// Message header.
    header: ControlMessageHeader,
    /// Message body.
    body:   Box<ControlMessageBody>,
}

impl ControlMessage {
    /// Create a new ACK Control Protocol message.
    pub fn ack(msg_id: u16, err: u32) -> ControlMessage {
        ControlMessage::new(msg_id, ControlMessageType::ACK, AckMessage::new(err))
    }

    /// Create a new HUP Control Protocol message.
    pub fn hup(msg_id: u16, session_id: u32, error_code: u32) -> ControlMessage {
        ControlMessage::new(
            msg_id,
            ControlMessageType::HUP,
            HupMessage::new(
                session_id,
                error_code))
    }

    /// Create a new STATUS Control Protocol message.
    pub fn status(
        msg_id: u16,
        request_id: u16,
        status_flags: u32,
        active_sessions: u32) -> ControlMessage {
        ControlMessage::new(
            msg_id,
            ControlMessageType::STATUS,
            StatusMessage::new(
                request_id,
                status_flags,
                active_sessions))
    }

    /// Create a new SCAN_REPORT Control Protocol message.
    pub fn scan_report(
        msg_id: u16,
        request_id: u16,
        report: ScanReport) -> ControlMessage {
        ControlMessage::new(
            msg_id,
            ControlMessageType::SCAN_REPORT,
            ScanReportMessage::new(
                request_id,
                report))
    }

    /// Create a new PING Control Protocol message.
    pub fn ping(msg_id: u16) -> ControlMessage {
        ControlMessage::new(
            msg_id,
            ControlMessageType::PING,
            EmptyMessage)
    }

    /// Create a new Control Protocol message.
    fn new<B>(msg_id: u16, msg_type: ControlMessageType, body: B) -> ControlMessage
        where B: ControlMessageBody + 'static {
        ControlMessage {
            header: ControlMessageHeader::new(msg_id, msg_type.code()),
            body:   Box::new(body),
        }
    }

    /// Get reference to the message header.
    pub fn header(&self) -> ControlMessageHeader {
        self.header
    }

    /// Get reference to the message body or None if the type of the message body does not match
    /// to the expected one.
    pub fn body<T: ControlMessageBody + 'static>(&self) -> Option<&T> {
        self.body.as_any()
            .downcast_ref()
    }

    /// Decode message body from given data according to a given message type.
    fn decode_body(mtype: ControlMessageType, bytes: &[u8]) -> Result<Box<ControlMessageBody>, DecodeError> {
        match mtype {
            ControlMessageType::ACK             => ControlMessage::decode_ack_message(bytes),
            ControlMessageType::PING            => ControlMessage::decode_empty_message(bytes),
            ControlMessageType::REDIRECT        => ControlMessage::decode_redirect_message(bytes),
            ControlMessageType::HUP             => ControlMessage::decode_hup_message(bytes),
            ControlMessageType::RESET_SVC_TABLE => ControlMessage::decode_empty_message(bytes),
            ControlMessageType::SCAN_NETWORK    => ControlMessage::decode_empty_message(bytes),
            ControlMessageType::GET_STATUS      => ControlMessage::decode_empty_message(bytes),
            ControlMessageType::GET_SCAN_REPORT => ControlMessage::decode_empty_message(bytes),
            ControlMessageType::UNKNOWN         => Err(DecodeError::from("unknown Arrow Control Protocol message type")),
            _                                   => Err(DecodeError::from("unexpected Arrow Control Protocol message type")),
        }
    }

    /// Decode an ACK message from given data.
    fn decode_ack_message(bytes: &[u8]) -> Result<Box<ControlMessageBody>, DecodeError> {
        if let Some(msg) = AckMessage::from_bytes(bytes)? {
            Ok(Box::new(msg))
        } else {
            panic!("unable to decode an Arrow Control Protocol ACK message")
        }
    }

    /// Decode a REDIRECT message from given data.
    fn decode_redirect_message(bytes: &[u8]) -> Result<Box<ControlMessageBody>, DecodeError> {
        if let Some(msg) = RedirectMessage::from_bytes(bytes)? {
            Ok(Box::new(msg))
        } else {
            panic!("unable to decode an Arrow Control Protocol REGISTER message")
        }
    }

    /// Decode a HUP message from given data.
    fn decode_hup_message(bytes: &[u8]) -> Result<Box<ControlMessageBody>, DecodeError> {
        if let Some(msg) = HupMessage::from_bytes(bytes)? {
            Ok(Box::new(msg))
        } else {
            panic!("unable to decode an Arrow Control Protocol HUP message")
        }
    }

    /// Decode an empty message from given data (i.e. just check there is no data).
    fn decode_empty_message(bytes: &[u8]) -> Result<Box<ControlMessageBody>, DecodeError> {
        if bytes.len() == 0 {
            Ok(Box::new(EmptyMessage))
        } else {
            Err(DecodeError::from("malformed Arrow Control Protocol message"))
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

impl ArrowMessageBody for ControlMessage {
}

impl FromBytes for ControlMessage {
    fn from_bytes(bytes: &[u8]) -> Result<Option<ControlMessage>, DecodeError> {
        let hsize = mem::size_of::<ControlMessageHeader>();

        if bytes.len() < hsize {
            return Err(DecodeError::from("malformed Arrow Control Protocol message"));
        }

        if let Some(header) = ControlMessageHeader::from_bytes(&bytes[..hsize])? {
            let body = ControlMessage::decode_body(
                header.message_type(),
                &bytes[hsize..])?;

            let msg = ControlMessage {
                header: header,
                body:   body,
            };

            Ok(Some(msg))
        } else {
            panic!("unable to decode an Arrow Control Protocol message")
        }
    }
}
