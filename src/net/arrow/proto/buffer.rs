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

use bytes::{Bytes, BytesMut};

/// Common trait for input buffer implementations.
pub trait InputBuffer {
    /// Get currently buffered data.
    fn as_bytes(&self) -> &[u8];

    /// Drop a given number of bytes from the begining of the buffer.
    fn drop(&mut self, len: usize);
}

impl InputBuffer for Bytes {
    fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }

    fn drop(&mut self, mut len: usize) {
        if len > self.len() {
            len = self.len();
        }

        self.split_to(len);
    }
}

impl InputBuffer for BytesMut {
    fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }

    fn drop(&mut self, mut len: usize) {
        if len > self.len() {
            len = self.len();
        }

        self.split_to(len);
    }
}

/// Common trait for outpur buffer implementations.
pub trait OutputBuffer {
    /// Append given data at the end of the buffer.
    fn append(&mut self, data: &[u8]);
}

impl OutputBuffer for BytesMut {
    fn append(&mut self, data: &[u8]) {
        self.extend(data);
    }
}
