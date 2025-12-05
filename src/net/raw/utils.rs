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

use std::{
    io::{self, Write},
    mem, slice,
};

/// Common trait for serializable objects.
pub trait Serialize {
    /// Serialize this object using a given writer.
    fn serialize(&self, w: &mut dyn Write) -> io::Result<()>;
}

impl Serialize for Box<[u8]> {
    fn serialize(&self, w: &mut dyn Write) -> io::Result<()> {
        w.write_all(self.as_ref())
    }
}

/// Sum a given Sized type instance as 16-bit unsigned big endian numbers.
pub fn sum_type<T: Sized>(data: &T) -> u32 {
    let size = mem::size_of::<T>();
    let ptr = data as *const T;
    unsafe { sum_raw_be(ptr as *const u8, size) }
}

/// Sum a given slice of Sized type instances as 16-bit unsigned big endian
/// numbers.
pub fn sum_slice<T: Sized>(data: &[T]) -> u32 {
    let size = mem::size_of_val(data);
    let ptr = data.as_ptr();
    unsafe { sum_raw_be(ptr as *const u8, size) }
}

/// Sum given raw data as 16-bit unsigned big endian numbers.
#[allow(clippy::missing_safety_doc)]
pub unsafe fn sum_raw_be(data: *const u8, size: usize) -> u32 {
    let mut sum: u32 = 0;

    let count = size >> 1;

    for idx in 0..count {
        let val = unsafe { std::ptr::read_unaligned(data.add(idx << 1) as *const u16) };

        let val = u16::from_be(val);

        sum = sum.wrapping_add(val as u32);
    }

    let slice = unsafe { slice::from_raw_parts(data, size) };

    if (size & 0x01) != 0 {
        sum.wrapping_add((slice[size - 1] as u32) << 8)
    } else {
        sum
    }
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
    use super::*;

    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    #[repr(packed)]
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
