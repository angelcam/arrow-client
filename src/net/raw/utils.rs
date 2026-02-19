// Copyright 2025 Angelcam, Inc.
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

//! Common functions used throughout the `net::raw::*` modules.

use bytes::{Bytes, BytesMut};
use zerocopy::{FromBytes, Immutable, IntoBytes, byteorder::network_endian::U16};

/// Common trait for serializable objects.
pub trait Serialize {
    /// Serialize this object.
    fn serialize(&self, buf: &mut BytesMut);
}

impl Serialize for Bytes {
    fn serialize(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(self);
    }
}

/// Sum a given Sized type instance as 16-bit unsigned big endian numbers.
pub fn sum_type<T>(data: &T) -> u32
where
    T: Immutable + IntoBytes,
{
    sum_be_bytes(data.as_bytes())
}

/// Sum a given slice of Sized type instances as 16-bit unsigned big endian
/// numbers.
pub fn sum_slice<T>(data: &[T]) -> u32
where
    T: Immutable + IntoBytes,
{
    sum_be_bytes(data.as_bytes())
}

/// Sum given data as 16-bit unsigned big endian numbers.
fn sum_be_bytes(data: &[u8]) -> u32 {
    let count = data.len() >> 1;

    let mut sum: u32 = 0;

    let (elems, rest) = <[U16]>::ref_from_prefix_with_elems(data, count)
        .expect("unable to convert input data into a sequence of 16-bit numbers");

    for elem in elems {
        sum = sum.wrapping_add(elem.get() as u32);
    }

    // NOTE: There will be at most one byte left at the end.
    for elem in rest {
        sum = sum.wrapping_add((*elem as u32) << 8);
    }

    sum
}

/// Convert given 32-bit unsigned sum into 16-bit unsigned checksum.
pub fn sum_to_checksum(sum: u32) -> u16 {
    let mut checksum = sum;
    while (checksum & 0xffff_0000) != 0 {
        let hw = checksum >> 16;
        let lw = checksum & 0xffff;
        checksum = lw + hw;
    }

    !checksum as u16
}

#[cfg(test)]
mod tests {
    use zerocopy::{Immutable, IntoBytes};

    use super::*;

    #[derive(Copy, Clone, Debug, Eq, PartialEq, Immutable, IntoBytes)]
    #[repr(C)]
    struct TestType {
        b1: u8,
        b2: u8,
    }

    #[test]
    fn test_sum_type() {
        let val = TestType { b1: 1, b2: 2 };
        assert_eq!(0x0102, sum_type(&val));
    }

    #[test]
    fn test_sum_slice() {
        let val = TestType { b1: 1, b2: 2 };
        let vec = vec![val, val];
        assert_eq!(0x0204, sum_slice(&vec));
    }

    #[test]
    fn test_sum_to_checksum() {
        assert_eq!(!0x0000_3333, sum_to_checksum(0x1111_2222));
    }
}
