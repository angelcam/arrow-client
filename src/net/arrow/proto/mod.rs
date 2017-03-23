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
pub mod buffer;
pub mod error;
pub mod utils;

use net::arrow::proto::error::DecodeError;
use net::arrow::proto::buffer::{InputBuffer, OutputBuffer};

/// Currently supported version of the Arrow protocol.
pub const ARROW_PROTOCOL_VERSION: u8 = 1;

/// Type alias for a vector of bytes.
pub type ByteVec = Vec<u8>;

/// Common trait for objects that can be encoded as a sequence of bytes.
pub trait Encode {
    /// Serialize this object into a given buffer.
    fn encode(&self, buf: &mut OutputBuffer);
}

impl<T: AsRef<[u8]>> Encode for T {
    fn encode(&self, buf: &mut OutputBuffer) {
        buf.append(self.as_ref())
    }
}

/// Common trait for types that can be decoded from a sequence of bytes.
pub trait FromBytes : Sized {
    /// Deserialize an object from a given buffer if possible.
    fn from_bytes(bytes: &[u8]) -> Result<Option<Self>, DecodeError>;
}

/// Common trait for types that can be decoded from a sequence of bytes.
pub trait Decode : Sized {
    /// Deserialize an object from a given buffer if possible and drop the used data.
    fn decode(buf: &mut InputBuffer) -> Result<Option<Self>, DecodeError>;
}
