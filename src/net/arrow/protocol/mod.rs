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

//! Common Arrow Protocol definitions.

pub mod control;
pub mod svc_table;

pub use self::control::ControlMessage;
pub use self::control::ControlMessageHeader;
pub use self::control::ControlMessageBody;
pub use self::control::ControlMessageParser;
pub use self::control::ControlMessageType;

pub use self::control::EmptyBody;

pub use self::control::RegisterMessage;
pub use self::control::RegisterMessageHeader;

pub use self::control::HupMessage;

pub use self::control::StatusMessage;

pub use self::svc_table::Service;
pub use self::svc_table::ServiceTable;

use std::io;
use std::mem;

use std::io::Write;

use utils;

use utils::Serialize;
use net::arrow::error::{Result, ArrowError};

/// Common trait for Arrow Message payload types.
pub trait ArrowMessageBody : Serialize {
    /// Get body size in bytes.
    fn len(&self) -> usize;
}

/// Arrow Message header.
#[derive(Debug, Copy, Clone)]
#[repr(packed)]
pub struct ArrowMessageHeader {
    /// Arrow Protocol major version.
    pub version: u8,
    /// Service ID.
    pub service: u16,
    /// Session ID (note: the upper 8 bits are reserved).
    pub session: u32,
    /// Payload size.
    size:        u32,
}

impl ArrowMessageHeader {
    /// Create a new Arrow Message header with a given service ID, session ID 
    /// and payload size.
    fn new(service: u16, session: u32, size: u32) -> ArrowMessageHeader {
        ArrowMessageHeader {
            version: 0,
            service: service,
            session: session & ((1 << 24) - 1),
            size:    size
        }
    }
    
    /// Deserialize an Arrow Message header.
    fn from_bytes(slice: &[u8]) -> Result<ArrowMessageHeader> {
        assert_eq!(slice.len(), mem::size_of::<ArrowMessageHeader>());
        let ptr    = slice.as_ptr() as *const ArrowMessageHeader;
        let header = unsafe { &*ptr };
        
        let res = ArrowMessageHeader {
            version: header.version,
            service: u16::from_be(header.service),
            session: u32::from_be(header.session) & ((1 << 24) - 1),
            size:    u32::from_be(header.size)
        };
        
        if res.version == 0 {
            Ok(res)
        } else {
            Err(ArrowError::from("unsupported Arrow Protocol version"))
        }
    }
}

impl Serialize for ArrowMessageHeader {
    fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let be_header = ArrowMessageHeader {
            version: self.version,
            service: self.service.to_be(),
            session: self.session.to_be(),
            size:    self.size.to_be()
        };
        
        w.write_all(utils::as_bytes(&be_header))
    }
}

/// Arrow Message envelope.
#[derive(Debug, Clone)]
pub struct ArrowMessage<B: ArrowMessageBody> {
    /// Message header.
    header: ArrowMessageHeader,
    /// Payload.
    body:   B,
}

impl<B: ArrowMessageBody> ArrowMessage<B> {
    /// Create a new Arrow Message with a given service ID, session ID and 
    /// payload.
    pub fn new(service: u16, session: u32, body: B) -> ArrowMessage<B> {
        ArrowMessage {
            header: ArrowMessageHeader::new(service, session, 0),
            body:   body
        }
    }
    
    /// Get message header.
    pub fn header(&self) -> &ArrowMessageHeader {
        &self.header
    }
}

impl<B: ArrowMessageBody> Serialize for ArrowMessage<B> {
    fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let header = ArrowMessageHeader::new(
            self.header.service,
            self.header.session,
            self.body.len() as u32);
        
        try!(header.serialize(w));
        
        self.body.serialize(w)
    }
}

/// Arrow Message parser.
/// 
/// This structure allows to read Arrow Messages from continuous streams.
pub struct ArrowMessageParser {
    header:   Option<ArrowMessageHeader>,
    buffer:   Vec<u8>,
    expected: usize,
}

impl ArrowMessageParser {
    /// Create a new Arrow Message parser.
    pub fn new() -> ArrowMessageParser {
        ArrowMessageParser {
            header:   None,
            buffer:   Vec::new(),
            expected: 0
        }
    }
    
    /// Check if the last message is complete.
    pub fn is_complete(&self) -> bool {
        self.header.is_some() && self.expected == 0
    }
    
    /// Process a new chunk of data and return the number of bytes used.
    pub fn add(&mut self, data: &[u8]) -> Result<usize> {
        let mut consumed = 0;
        
        if self.header.is_none() {
            consumed += try!(self.read_header(data));
            if let Some(header) = self.header {
                self.expected = header.size as usize;
            }
        }
        
        if self.header.is_some() {
            consumed += self.read_body(&data[consumed..]);
        }
        
        Ok(consumed)
    }
    
    /// Clear the last message and prepare the parser for a new one.
    pub fn clear(&mut self) {
        self.buffer.clear();
        
        self.expected = 0;
        self.header   = None;
    }
    
    /// Get last message header.
    pub fn header(&self) -> Option<&ArrowMessageHeader> {
        match self.header {
            Some(ref header) => Some(header),
            None => None
        }
    }
    
    /// Get last message body.
    pub fn body(&self) -> Option<&[u8]> {
        let header_size = mem::size_of::<ArrowMessageHeader>();
        if self.is_complete() {
            Some(&self.buffer[header_size..])
        } else {
            None
        }
    }
    
    /// Read header chunk.
    fn read_header(&mut self, data: &[u8]) -> Result<usize> {
        let size         = mem::size_of::<ArrowMessageHeader>();
        let mut consumed = size - self.buffer.len();
        
        if consumed > data.len() {
            consumed = data.len();
        }
        
        let data = &data[..consumed];
        
        self.buffer.extend(data.iter());
        
        if size == self.buffer.len() {
            self.header = Some(try!(
                ArrowMessageHeader::from_bytes(&self.buffer)));
        }
        
        Ok(consumed)
    }
    
    /// Read body chunk.
    fn read_body(&mut self, data: &[u8]) -> usize {
        let mut consumed = self.expected;
        
        if consumed > data.len() {
            consumed = data.len();
        }
        
        let data = &data[..consumed];
        
        self.buffer.extend(data.iter());
        self.expected -= consumed;
        
        consumed
    }
}

impl ArrowMessageBody for Vec<u8> {
    fn len(&self) -> usize {
        Vec::<u8>::len(self)
    }
}

impl<'a> ArrowMessageBody for &'a [u8] {
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::Serialize;
    use net::utils::WriteBuffer;
    
    #[test]
    fn test_message_serialization() {
        let msg_data = [0x00,                    // version
                        0x10, 0x22,              // svc_id
                        0x00, 0x34, 0x56, 0x78,  // session_id
                        0x00, 0x00, 0x00, 0x02,  // body_size
                        0xab, 0xcd];             // body
        
        let message = ArrowMessage::new(0x1022, 0x12345678, vec![0xab, 0xcd]);
        
        let mut buf = WriteBuffer::new(0);
        
        message.serialize(&mut buf).unwrap();
        
        assert_eq!(&msg_data, buf.as_bytes());
    }
    
    #[test]
    fn test_message_deserialization() {
        let mut parser = ArrowMessageParser::new();
        let msg        = [0x00,                    // version
                          0x10, 0x22,              // svc_id
                          0x12, 0x34, 0x56, 0x78,  // session_id
                          0x00, 0x00, 0x00, 0x02,  // body_size
                          0xab, 0xcd];             // body
        
        assert_eq!(parser.is_complete(), false);
        assert!(parser.header().is_none());
        assert!(parser.body().is_none());
        
        assert_eq!(parser.add(&msg).unwrap(), msg.len());
        
        assert_eq!(parser.is_complete(), true);
        assert!(parser.header().is_some());
        assert!(parser.body().is_some());
        
        {
            let header = parser.header().unwrap();
            
            assert_eq!(header.version, 0);
            assert_eq!(header.service, 0x1022);
            assert_eq!(header.session, 0x00345678);
        }
        
        {
            let body = parser.body().unwrap();
            
            assert_eq!(body, &[0xab, 0xcd]);
        }
        
        assert_eq!(parser.add(&msg).unwrap(), 0);
        
        parser.clear();
        
        assert_eq!(parser.is_complete(), false);
        assert!(parser.header().is_none());
        assert!(parser.body().is_none());
        
        assert_eq!(parser.add(&msg[..11]).unwrap(), 11);
        
        assert_eq!(parser.is_complete(), false);
        assert!(parser.header().is_some());
        assert!(parser.body().is_none());
        
        assert_eq!(parser.add(&msg[11..]).unwrap(), 2);
        
        assert_eq!(parser.is_complete(), true);
        assert!(parser.header().is_some());
        assert!(parser.body().is_some());
    }
}
