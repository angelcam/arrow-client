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

//! Common util functions.

#[macro_use]
pub mod logger;

pub mod config;

use std::io;
use std::ptr;
use std::mem;
use std::fmt;
use std::slice;
use std::process;

use std::ffi::CStr;
use std::error::Error;
use std::ops::Deref;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::fmt::{Debug, Display, Formatter};

use utils::logger::{Logger, Severity};

/// General purpose runtime error.
#[derive(Debug, Clone)]
pub struct RuntimeError {
    msg: String,
}

impl Error for RuntimeError {
    fn description(&self) -> &str {
        &self.msg
    }
}

impl Display for RuntimeError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        f.write_str(&self.msg)
    }
}

impl<'a> From<&'a str> for RuntimeError {
    fn from(msg: &'a str) -> RuntimeError {
        RuntimeError { msg: msg.to_string() }
    }
}

impl From<String> for RuntimeError {
    fn from(msg: String) -> RuntimeError {
        RuntimeError { msg: msg }
    }
}

/// Arc<Mutex<T>> shorthand.
#[derive(Clone)]
pub struct Shared<T> {
    object: Arc<Mutex<T>>,
}

impl<T> Shared<T> {
    /// Create a new shared object.
    pub fn new(obj: T) -> Shared<T> {
        Shared {
            object: Arc::new(Mutex::new(obj))
        }
    }
}

impl<T> Deref for Shared<T> {
    type Target = Mutex<T>;
    
    fn deref(&self) -> &Mutex<T> {
        self.object.deref()
    }
}

unsafe impl<T> Send for Shared<T> { }

/// Common trait for serializable objects.
pub trait Serialize {
    /// Serialize this object using a given writer.
    fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()>;
}

impl Serialize for u8 {
    fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(as_bytes(&self.to_be()))
    }
}

impl Serialize for i8 {
    fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(as_bytes(&self.to_be()))
    }
}

impl Serialize for u16 {
    fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(as_bytes(&self.to_be()))
    }
}

impl Serialize for i16 {
    fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(as_bytes(&self.to_be()))
    }
}

impl Serialize for u32 {
    fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(as_bytes(&self.to_be()))
    }
}

impl Serialize for i32 {
    fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(as_bytes(&self.to_be()))
    }
}

impl Serialize for u64 {
    fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(as_bytes(&self.to_be()))
    }
}

impl Serialize for i64 {
    fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(as_bytes(&self.to_be()))
    }
}

impl Serialize for usize {
    fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(as_bytes(&self.to_be()))
    }
}

impl Serialize for isize {
    fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(as_bytes(&self.to_be()))
    }
}

impl Serialize for Vec<u8> {
    fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(self)
    }
}

impl<'a> Serialize for &'a [u8] {
    fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(self)
    }
}

/// Efficient function for copying data from one slice to another.
///
/// It copies all data from the src slice into the dst slice.
///
/// # Panics
/// The function panics when src.len() > dst.len()
pub fn memcpy<T: Copy>(dst: &mut [T], src: &[T]) {
    assert!(src.len() <= dst.len());
    unsafe {
        ptr::copy(src.as_ptr(), dst.as_mut_ptr(), src.len());
    }
}

/// Get slice of bytes representing a given object.
pub fn as_bytes<'a, T: Sized>(val: &'a T) -> &'a [u8] {
    let ptr  = val as *const T;
    let size = mem::size_of::<T>();
    unsafe {
        slice::from_raw_parts(ptr as *const u8, size)
    }
}

/// Convert a given slice of Sized type instances to a slice of bytes.
pub fn slice_as_bytes<'a, T: Sized>(data: &'a [T]) -> &'a [u8] {
    let ptr  = data.as_ptr();
    let size = mem::size_of::<T>();
    unsafe {
        slice::from_raw_parts(ptr as *const u8, size * data.len())
    }
}

/// Convert a given typed pointer into a new vector (copying the dats).
pub unsafe fn vec_from_raw_parts<T: Clone>(
    ptr: *const T, 
    len: usize) -> Vec<T> {
    slice::from_raw_parts(ptr, len)
        .to_vec()
}

/// Convert a given C-string pointer to a new instance of String.
pub unsafe fn cstr_to_string(ptr: *const i8) -> String {
    let cstr  = CStr::from_ptr(ptr);
    let slice = String::from_utf8_lossy(cstr.to_bytes());
    slice.to_string()
}

/// Exit application printing a given error.
pub fn error<T: Error + Debug>(err: T, exit_code: i32) -> ! {
    println!("ERROR: {}", err.description());
    process::exit(exit_code);
}

/// Unwrap a given result or exit the process printing the error.
pub fn result_or_error<T, E>(res: Result<T, E>, exit_code: i32) -> T 
    where E: Error + Debug {
    match res {
        Ok(res)  => res,
        Err(err) => error(err, exit_code)
    }
}

/// Unwrap a given result or log an error with a given severity and return None.
pub fn result_or_log<L, T, E>(
    logger: &mut L, 
    severity: Severity, 
    res: Result<T, E>) -> Option<T>
    where E: Error + Debug,
          L: Logger {
    match res {
        Err(err) => {
            log!(logger, severity, "{}", err.description());
            None
        },
        Ok(res)  => Some(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use utils::logger::*;
    
    struct DummyLogger;
    
    impl Logger for DummyLogger {
        fn log(&mut self, _: &str, _: u32, _: Severity, _: &str) { }
        fn set_level(&mut self, _: Severity) -> &mut Self { self }
        fn get_level(&self) -> Severity { Severity::DEBUG }
    }
    
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    #[repr(packed)]
    struct TestType {
        b1: u8,
        b2: u8,
    }
    
    #[test]
    fn test_vec_from_raw_parts() {
        let val  = TestType { b1: 1, b2: 2 };
        let vec  = vec![val, val];
        let ptr  = vec.as_ptr();
        let vec2 = unsafe { vec_from_raw_parts(ptr, vec.len()) };
        
        assert_eq!(vec, vec2);
    }
    
    #[test]
    fn test_cstr_to_string() {
        let cstr = CString::new("hello").unwrap();
        unsafe {
            assert!("hello" == &cstr_to_string(cstr.as_ptr() as *const i8));
            assert!("world" != &cstr_to_string(cstr.as_ptr() as *const i8));
        }
    }
    
    #[test]
    fn test_result_or_error() {
        assert_eq!(1, result_or_error::<i32, RuntimeError>(Ok(1), 0));
    }
    
    #[test]
    fn test_result_or_log() {
        assert_eq!(Some(1), result_or_log::<DummyLogger, i32, RuntimeError>(
            &mut DummyLogger, Severity::WARN, Ok(1)));
        assert_eq!(None, result_or_log::<DummyLogger, i32, RuntimeError>(
            &mut DummyLogger, Severity::WARN, Err(RuntimeError::from("foo"))));
    }
}
