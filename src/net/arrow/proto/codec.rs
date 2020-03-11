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

use bytes::BytesMut;

use tokio_util::codec::{Decoder, Encoder};

use crate::net::arrow::error::ArrowError;
use crate::net::arrow::proto::error::DecodeError;
use crate::net::arrow::proto::msg::ArrowMessage;

/// Common trait for objects that can be encoded as a sequence of bytes.
pub trait Encode {
    /// Serialize this object into a given buffer.
    fn encode(&self, buf: &mut BytesMut);
}

impl<T: AsRef<[u8]>> Encode for T {
    fn encode(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(self.as_ref())
    }
}

/// Common trait for types that can be decoded from a sequence of bytes.
pub trait FromBytes: Sized {
    /// Deserialize an object from a given buffer if possible.
    fn from_bytes(bytes: &[u8]) -> Result<Option<Self>, DecodeError>;
}

/// Common trait for types that can be decoded from a sequence of bytes.
pub trait Decode: Sized {
    /// Deserialize an object from a given buffer if possible and drop the used data.
    fn decode(buf: &mut BytesMut) -> Result<Option<Self>, DecodeError>;
}

/// ArrowMessage codec used in tokio.
pub struct ArrowCodec;

impl Decoder for ArrowCodec {
    type Item = ArrowMessage;
    type Error = ArrowError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        ArrowMessage::decode(src).map_err(ArrowError::from)
    }
}

impl Encoder<ArrowMessage> for ArrowCodec {
    type Error = ArrowError;

    fn encode(&mut self, item: ArrowMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        item.encode(dst);
        Ok(())
    }
}
