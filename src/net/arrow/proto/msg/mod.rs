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

pub mod control;

use std::mem;

use utils;

use utils::AsAny;

use net::arrow::proto::ARROW_PROTOCOL_VERSION;
use net::arrow::proto::codec::{FromBytes, Decode, Encode};
use net::arrow::proto::buffer::{InputBuffer, OutputBuffer};
use net::arrow::proto::msg::control::ControlMessage;
use net::arrow::proto::error::DecodeError;

/// Common trait for message body types.
pub trait MessageBody : Encode {
    /// Get size of the body in bytes.
    fn len(&self) -> usize;
}

impl<T: AsRef<[u8]>> MessageBody for T {
    fn len(&self) -> usize {
        self.as_ref()
            .len()
    }
}

/// Arrow Message header.
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
            version: ARROW_PROTOCOL_VERSION,
            service: service,
            session: session & ((1 << 24) - 1),
            size:    size
        }
    }
}

impl Encode for ArrowMessageHeader {
    fn encode(&self, buf: &mut OutputBuffer) {
        let be_header = ArrowMessageHeader {
            version: self.version,
            service: self.service.to_be(),
            session: self.session.to_be(),
            size:    self.size.to_be()
        };

        buf.append(utils::as_bytes(&be_header))
    }
}

impl FromBytes for ArrowMessageHeader {
    fn from_bytes(bytes: &[u8]) -> Result<Option<ArrowMessageHeader>, DecodeError> {
        assert_eq!(bytes.len(), mem::size_of::<ArrowMessageHeader>());

        let ptr    = bytes.as_ptr() as *const ArrowMessageHeader;
        let header = unsafe { &*ptr };

        let res = ArrowMessageHeader {
            version: header.version,
            service: u16::from_be(header.service),
            session: u32::from_be(header.session) & ((1 << 24) - 1),
            size:    u32::from_be(header.size)
        };

        if res.version == ARROW_PROTOCOL_VERSION {
            Ok(Some(res))
        } else {
            Err(DecodeError::from("unsupported Arrow Protocol version"))
        }
    }
}

/// Common trait for Arrow Message body implementations.
pub trait ArrowMessageBody : MessageBody + AsAny + Send {
}

impl ArrowMessageBody for Vec<u8> {
}

/// Arrow Message.
pub struct ArrowMessage {
    /// Message header.
    header: ArrowMessageHeader,
    /// Message body.
    body:   Box<ArrowMessageBody>,
}

impl ArrowMessage {
    /// Create a new Arrow Message with a given service ID, session ID and payload.
    pub fn new<B>(service: u16, session: u32, body: B) -> ArrowMessage
        where B: ArrowMessageBody + 'static {
        ArrowMessage {
            header: ArrowMessageHeader::new(service, session, 0),
            body:   Box::new(body)
        }
    }

    /// Get reference to the message header.
    pub fn header(&self) -> &ArrowMessageHeader {
        &self.header
    }

    /// Get reference to the message body or None if the type of the message body does not match
    /// to the expected one.
    pub fn body<T: ArrowMessageBody + 'static>(&self) -> Option<&T> {
        self.body.as_any()
            .downcast_ref()
    }
}

impl Encode for ArrowMessage {
    fn encode(&self, buf: &mut OutputBuffer) {
        let header = ArrowMessageHeader::new(
            self.header.service,
            self.header.session,
            self.body.len() as u32);

        header.encode(buf);

        self.body.encode(buf)
    }
}

impl FromBytes for ArrowMessage {
    fn from_bytes(bytes: &[u8]) -> Result<Option<ArrowMessage>, DecodeError> {
        let hsize = mem::size_of::<ArrowMessageHeader>();

        if bytes.len() < hsize {
            return Ok(None);
        }

        if let Some(header) = ArrowMessageHeader::from_bytes(&bytes[..hsize])? {
            let msize = header.size as usize + hsize;

            if bytes.len() < msize {
                return Ok(None);
            }

            let payload = &bytes[hsize..msize];

            let body: Box<ArrowMessageBody>;

            if header.service == 0 {
                if let Some(cmsg) = ControlMessage::from_bytes(payload)? {
                    body = Box::new(cmsg);
                } else {
                    panic!("unable to decode an Arrow Control Protocol message");
                }
            } else {
                body = Box::new(payload.to_vec());
            }

            let msg = ArrowMessage {
                header: header,
                body:   body,
            };

            Ok(Some(msg))
        } else {
            panic!("unable to decode an Arrow Message header")
        }
    }
}

impl Decode for ArrowMessage {
    fn decode(buf: &mut InputBuffer) -> Result<Option<ArrowMessage>, DecodeError> {
        let msg = ArrowMessage::from_bytes(buf.as_bytes())?;

        if let Some(ref msg) = msg {
            buf.drop(msg.header.size as usize + mem::size_of::<ArrowMessageHeader>());
        }

        Ok(msg)
    }
}
