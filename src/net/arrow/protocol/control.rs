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

//! Common Arrow Control Protocol definitions.

use std::io;
use std::mem;

use std::io::Write;

use utils;

use utils::Serialize;
use net::arrow::error::{ArrowError, Result};
use net::arrow::protocol::{ArrowMessageBody, ServiceTable, ScanReportMessage};

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

pub const ACK_NO_ERROR:                     u32 = 0x00000000;
pub const ACK_UNSUPPORTED_PROTOCOL_VERSION: u32 = 0x00000001;
pub const ACK_UNAUTHORIZED:                 u32 = 0x00000002;
pub const ACK_CONNECTION_ERROR:             u32 = 0x00000003;
pub const ACK_UNSUPPORTED_METHOD:           u32 = 0x00000004;
pub const ACK_INTERNAL_SERVER_ERROR:        u32 = 0xffffffff;

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

/// Common trait for Control Protocol payload types.
pub trait ControlMessageBody : Serialize {
    /// Get body size in bytes.
    fn len(&self) -> usize;
}

/// Arrow Control Protocol message header.
#[derive(Debug, Copy, Clone)]
#[repr(packed)]
pub struct ControlMessageHeader {
    /// Message ID.
    pub msg_id:   u16,
    /// Message type.
    msg_type: u16,
}

impl ControlMessageHeader {
    /// Create a new Control Protocol message with a given message ID and 
    /// message type.
    fn new(msg_id: u16, msg_type: u16) -> ControlMessageHeader {
        ControlMessageHeader {
            msg_id:   msg_id,
            msg_type: msg_type
        }
    }
    
    /// Deserialize a Control Message header.
    fn from_bytes(data: &[u8]) -> ControlMessageHeader {
        assert_eq!(data.len(), mem::size_of::<ControlMessageHeader>());
        let ptr    = data.as_ptr() as *const ControlMessageHeader;
        let header = unsafe { &*ptr };
        
        ControlMessageHeader {
            msg_id:   u16::from_be(header.msg_id),
            msg_type: u16::from_be(header.msg_type)
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

impl Serialize for ControlMessageHeader {
    fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let be_header = ControlMessageHeader {
            msg_id:   self.msg_id.to_be(),
            msg_type: self.msg_type.to_be()
        };
        
        w.write_all(utils::as_bytes(&be_header))
    }
}

/// Arrow Control protocol message.
#[derive(Debug, Clone)]
pub struct ControlMessage<B: ControlMessageBody> {
    /// Message header.
    header: ControlMessageHeader,
    /// Message payload.
    body:   B,
}

impl<B: ControlMessageBody> ControlMessage<B> {
    /// Create a new Control Protocol message with a given message ID, message
    /// type and payload.
    pub fn new(msg_id: u16, msg_type: u16, body: B) -> ControlMessage<B> {
        ControlMessage {
            header: ControlMessageHeader::new(msg_id, msg_type),
            body:   body
        }
    }
    
    /// Get message header.
    pub fn header(&self) -> &ControlMessageHeader {
        &self.header
    }
}

impl<B: ControlMessageBody> Serialize for ControlMessage<B> {
    fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
        try!(self.header.serialize(w));
        self.body.serialize(w)
    }
}

impl<B: ControlMessageBody> ArrowMessageBody for ControlMessage<B> {
    fn len(&self) -> usize {
        mem::size_of::<ControlMessageHeader>() + self.body.len()
    }
}

/// Create a new ACK message with a given message ID and error code.
pub fn create_ack_message(msg_id: u16, err: u32) -> ControlMessage<u32> {
    ControlMessage::new(msg_id, CMSG_ACK, err)
}

/// Create a new PING message with a given message ID.
pub fn create_ping_message(msg_id: u16) -> ControlMessage<EmptyBody> {
    ControlMessage::new(msg_id, CMSG_PING, EmptyBody)
}

/// Create a new REGISTER message for a given message ID and message body.
pub fn create_register_message(
    msg_id: u16, 
    body: RegisterMessage) -> ControlMessage<RegisterMessage> {
    ControlMessage::new(msg_id, CMSG_REGISTER, body)
}

/// Create a new UPDATE message for a given message ID and service table.
pub fn create_update_message(
    msg_id: u16, 
    svc_table: ServiceTable) -> ControlMessage<ServiceTable> {
    ControlMessage::new(msg_id, CMSG_UPDATE, svc_table.clone())
}

/// Create a new HUP message for a given message ID, session ID and error code.
pub fn create_hup_message(
    msg_id: u16,
    session_id: u32,
    error_code: u32) -> ControlMessage<HupMessage> {
    ControlMessage::new(msg_id, CMSG_HUP, 
        HupMessage::new(session_id, error_code))
}

/// Create a new STATUS control message for a given message ID and message 
/// body.
pub fn create_status_message(
    msg_id: u16, 
    status_msg: StatusMessage) -> ControlMessage<StatusMessage> {
    ControlMessage::new(msg_id, CMSG_STATUS, status_msg)
}

/// Create a new SCAN_REPORT control message for a given message ID and message 
/// body.
pub fn create_scan_report_message(
    msg_id: u16,
    scan_report_msg: ScanReportMessage) -> ControlMessage<ScanReportMessage> {
    ControlMessage::new(msg_id, CMSG_SCAN_REPORT, scan_report_msg)
}

/// Arrow Control Protocol message parser.
pub struct ControlMessageParser<'a> {
    header: Option<ControlMessageHeader>,
    body:   Option<&'a [u8]>,
}

impl<'a> ControlMessageParser<'a> {
    /// Create a new Control Protocol message parser.
    pub fn new() -> ControlMessageParser<'a> {
        ControlMessageParser {
            header: None,
            body:   None
        }
    }
    
    /// Process given message data.
    pub fn process(&mut self, data: &'a [u8]) -> Result<()> {
        let header_size = mem::size_of::<ControlMessageHeader>();
        if data.len() < header_size {
            return Err(ArrowError::other("not enough data to parse an Arrow Control Protocol message"));
        }
        
        let header_data = &data[..header_size];
        let body_data   = &data[header_size..];
        let header      = ControlMessageHeader::from_bytes(header_data);
        
        self.header     = Some(header);
        self.body       = Some(body_data);
        
        Ok(())
    }
    
    /// Get message header of the last successfully parsed message.
    pub fn header(&self) -> &ControlMessageHeader {
        match self.header {
            Some(ref header) => header,
            None => panic!("no Control Protocol message has been processed yet")
        }
    }
    
    /// Get message body of the last successfully parsed message.
    pub fn body(&self) -> &[u8] {
        match self.body {
            Some(ref body) => body,
            None => panic!("no Control Protocol message has been processed yet")
        }
    }
}

impl ControlMessageBody for u32 {
    fn len(&self) -> usize {
        mem::size_of::<Self>()
    }
}

/// Dummy type representing empty payload.
#[derive(Debug, Copy, Clone)]
pub struct EmptyBody;

impl Serialize for EmptyBody {
    fn serialize<W: Write>(&self, _: &mut W) -> io::Result<()> {
        Ok(())
    }
}

impl ControlMessageBody for EmptyBody {
    fn len(&self) -> usize {
        0
    }
}

/// REGISTER message header.
#[derive(Debug, Copy, Clone)]
#[repr(packed)]
pub struct RegisterMessageHeader {
    /// Client identifier.
    pub uuid:     [u8; 16],
    /// Client MAC address.
    pub mac_addr: [u8; 6],
    /// Client passphrase.
    pub passwd:   [u8; 16],
}

impl RegisterMessageHeader {
    /// Create a new REGISTER message header.
    fn new(
        uuid: [u8; 16], 
        mac_addr: [u8; 6], 
        passwd: [u8; 16]) -> RegisterMessageHeader {
        RegisterMessageHeader {
            uuid:     uuid,
            mac_addr: mac_addr,
            passwd:   passwd
        }
    }
}

impl Serialize for RegisterMessageHeader {
    fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(utils::as_bytes(self))
    }
}

/// REGISTER message.
#[derive(Debug, Clone)]
pub struct RegisterMessage {
    /// Message header.
    header: RegisterMessageHeader,
    /// Service table.
    table:  ServiceTable,
}

impl RegisterMessage {
    /// Create a new REGISTER message.
    pub fn new(
        uuid: [u8; 16], 
        mac_addr: [u8; 6], 
        passwd: [u8; 16], 
        svc_table: ServiceTable) -> RegisterMessage {
        RegisterMessage {
            header: RegisterMessageHeader::new(uuid, mac_addr, passwd),
            table:  svc_table
        }
    }
    
    /// Get message header.
    pub fn header(&self) -> &RegisterMessageHeader {
        &self.header
    }
    
    /// Get service table.
    pub fn service_table(&self) -> &ServiceTable {
        &self.table
    }
}

impl Serialize for RegisterMessage {
    fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
        try!(self.header.serialize(w));
        self.table.serialize(w)
    }
}

impl ControlMessageBody for RegisterMessage {
    fn len(&self) -> usize {
        mem::size_of::<RegisterMessageHeader>() + self.table.len()
    }
}

/// HUP message.
#[derive(Debug, Copy, Clone)]
#[repr(packed)]
pub struct HupMessage {
    /// Session ID (note: the upper 8 bits are reserved).
    pub session_id: u32,
    /// Error code.
    pub error_code: u32,
}

impl HupMessage {
    /// Create a new HUP message for a given session ID and error code.
    fn new(session_id: u32, error_code: u32) -> HupMessage {
        HupMessage {
            session_id: session_id & ((1 << 24) - 1),
            error_code: error_code
        }
    }
    
    /// Parse a HUP message.
    pub fn from_bytes(data: &[u8]) -> Result<HupMessage> {
        let msg_size = mem::size_of::<HupMessage>();
        if data.len() != msg_size {
            return Err(ArrowError::other("invalid size of an Arrow Control Protocol HUP message"));
        }
        
        let ptr = data.as_ptr() as *const HupMessage;
        let msg = unsafe { &*ptr };
        let res = HupMessage {
            session_id: u32::from_be(msg.session_id),
            error_code: u32::from_be(msg.error_code)
        };
        
        Ok(res)
    }
}

impl Serialize for HupMessage {
    fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let be_msg = HupMessage {
            session_id: self.session_id.to_be(),
            error_code: self.error_code.to_be()
        };
        
        w.write_all(utils::as_bytes(&be_msg))
    }
}

impl ControlMessageBody for HupMessage {
    fn len(&self) -> usize {
        mem::size_of::<HupMessage>()
    }
}

/// Status flag indicating that there is a network scan currently in progress.
pub const STATUS_FLAG_SCAN: u32 = 0x00000001;

/// Status message.
#[derive(Debug, Copy, Clone)]
#[repr(packed)]
pub struct StatusMessage {
    request_id:      u16,
    status_flags:    u32,
    active_sessions: u32,
}

impl StatusMessage {
    pub fn new(
        request_id: u16, 
        status_flags: u32, 
        active_sessions: u32) -> StatusMessage {
        StatusMessage {
            request_id:      request_id,
            status_flags:    status_flags,
            active_sessions: active_sessions
        }
    }
}

impl Serialize for StatusMessage {
    fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let be_msg = StatusMessage {
            request_id:      self.request_id.to_be(),
            status_flags:    self.status_flags.to_be(),
            active_sessions: self.active_sessions.to_be()
        };
        
        w.write_all(utils::as_bytes(&be_msg))
    }
}

impl ControlMessageBody for StatusMessage {
    fn len(&self) -> usize {
        mem::size_of::<StatusMessage>()
    }
}

/// Parse a given ACK message body and return the error code.
pub fn parse_ack_message(msg: &[u8]) -> Result<u32> {
    if msg.len() == mem::size_of::<u32>() {
        let ptr = msg.as_ptr() as *const u32;
        let ack = unsafe {
            u32::from_be(*ptr)
        };
        
        Ok(ack)
    } else {
        Err(ArrowError::other("incorrect Control Protocol ACK message length"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::Serialize;
    use net::utils::WriteBuffer;
    use net::arrow::protocol::svc_table::ServiceTable;
    
    #[test]
    fn test_control_msg_serialization() {
        let ack_data  = [0x56, 0x78, 0x00, 0x00, 0xab, 0xcd, 0xef, 0x00];
        let ping_data = [0x12, 0x34, 0x00, 0x01];
        let ack       = create_ack_message(0x5678, 0xabcdef00);
        let ping      = create_ping_message(0x1234);
        
        let mut buf = WriteBuffer::new(0);
        
        ack.serialize(&mut buf).unwrap();
        
        assert_eq!(&ack_data, buf.as_bytes());
        
        buf.clear();
        
        ping.serialize(&mut buf).unwrap();
        
        assert_eq!(&ping_data, buf.as_bytes());
    }
    
    #[test]
    fn test_control_msg_deserialization() {
        let data       = [0x56, 0x78, 0x00, 0x00, 0xab, 0xcd, 0xef, 0x00];
        let mut parser = ControlMessageParser::new();
        
        parser.process(&data).unwrap();
        
        let header = parser.header();
        
        assert_eq!(header.msg_id, 0x5678);
        assert_eq!(header.message_type(), ControlMessageType::ACK);
        
        let body = parser.body();
        
        assert_eq!(body, &data[4..]);
    }
    
    #[test]
    fn test_register_msg_serialization() {
        let data = [
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            2, 2, 2, 2, 2, 2,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            0, 0, 
            0, 0, 
            0, 0, 0, 0, 0, 0, 
            4, 
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
            0, 0, 
            0];
        
        let svc_table = ServiceTable::new();
        let register  = RegisterMessage::new(
            [1u8; 16],
            [2u8; 6],
            [3u8; 16],
            svc_table);
        
        let mut buf = WriteBuffer::new(0);
        
        register.serialize(&mut buf).unwrap();
        
        let data_bytes: &[u8] = &data;
        
        assert_eq!(data_bytes, buf.as_bytes());
    }
}
