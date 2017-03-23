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

use std::ptr;

/// Common trait for input buffer implementations.
pub trait InputBuffer {
    /// Get currently buffered data.
    fn as_bytes(&self) -> &[u8];

    /// Drop a given number of bytes from the begining of the buffer.
    fn drop(&mut self, len: usize);
}

/// Common trait for outpur buffer implementations.
pub trait OutputBuffer {
    /// Append given data at the end of the buffer.
    fn append(&mut self, data: &[u8]);
}

/// Byte buffer for IO operations.
pub struct Buffer {
    /// Buffered data.
    buffer: Vec<u8>,
    /// Offset in the internal buffer.
    offset: usize,
}

impl Buffer {
    /// Create a new buffer.
    pub fn new() -> Buffer {
        Buffer {
            buffer: Vec::new(),
            offset: 0,
        }
    }

    /// Clear the buffer.
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.offset = 0;
    }
}

impl InputBuffer for Buffer {
    fn as_bytes(&self) -> &[u8] {
        &self.buffer[self.offset..]
    }

    fn drop(&mut self, len: usize) {
        if (self.offset + len) < self.buffer.len() {
            self.offset += len;
        } else {
            self.clear();
        }
    }
}

impl OutputBuffer for Buffer {
    fn append(&mut self, data: &[u8]) {
        let clen = self.buffer.len();

        // make some space in the buffer if the capacity is insufficient
        // in order to avoid reallocations
        if (clen + data.len()) > self.buffer.capacity() {
            let nlen = clen - self.offset;

            unsafe {
                let dst = self.buffer.as_mut_ptr();
                let src = self.buffer.as_ptr()
                    .offset(self.offset as isize);

                ptr::copy(src, dst, nlen);
                self.buffer.set_len(nlen);
            }
        }

        self.buffer.extend_from_slice(data);
    }
}

impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}
