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

pub mod logger;

use std::{ffi::CStr, os::raw::c_char};

/// Trait for converting `Copy` types to bytes.
pub trait AsBytes {
    /// Get the byte representation.
    fn as_bytes(&self) -> &[u8];
}

impl<T> AsBytes for T
where
    T: Copy,
{
    fn as_bytes(&self) -> &[u8] {
        let ptr = self as *const T;
        let size = std::mem::size_of_val(self);

        unsafe { std::slice::from_raw_parts(ptr as _, size) }
    }
}

impl<T> AsBytes for [T]
where
    T: Copy,
{
    fn as_bytes(&self) -> &[u8] {
        let ptr = self.as_ptr();
        let size = std::mem::size_of_val(self);

        unsafe { std::slice::from_raw_parts(ptr as _, size) }
    }
}

/// Trait for creating `Copy` type instances from bytes.
pub trait FromBytes {
    /// Copy the value from bytes.
    ///
    /// # Panics
    /// The method will panic if the provided byte slice is smaller than the
    /// size of the type.
    fn from_bytes(bytes: &[u8]) -> Self;
}

impl<T> FromBytes for T
where
    T: Copy,
{
    fn from_bytes(bytes: &[u8]) -> Self {
        let size = std::mem::size_of::<T>();

        assert!(bytes.len() >= size);

        unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const T) }
    }
}

/// Convert a given C-string pointer to a new instance of String.
///
/// # Safety
/// The given pointer MUST point to a NULL terminated C string.
pub unsafe fn cstr_to_string(ptr: *const c_char) -> String {
    let cstr = unsafe { CStr::from_ptr(ptr) };

    let slice = String::from_utf8_lossy(cstr.to_bytes());

    slice.to_string()
}

/// Convert a given typed pointer into a new vector (copying the data).
///
/// # Safety
/// The given pointer MUST point to an array that contains at least `len`
/// elements. Each element is expected to be of size T.
pub unsafe fn vec_from_raw_parts_unaligned<T: Copy>(ptr: *const T, len: usize) -> Vec<T> {
    let mut res = Vec::with_capacity(len);

    for idx in 0..len {
        let val = unsafe { std::ptr::read_unaligned(ptr.add(idx)) };

        res.push(val);
    }

    res
}
