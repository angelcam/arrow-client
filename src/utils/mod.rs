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

pub mod json;

#[macro_use]
pub mod logger;

pub mod string;

use std::fmt;
use std::mem;
use std::slice;

use std::any::Any;
use std::error::Error;
use std::ffi::CStr;
use std::fmt::{Debug, Display, Formatter};

use crate::utils::logger::{Logger, Severity};

/// Helper trait for getting Any reference to an object.
pub trait AsAny {
    /// Get Any reference to this object.
    fn as_any(&self) -> &dyn Any;

    /// Get mutable Any reference to this object.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

impl<T: Any + 'static> AsAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// General purpose runtime error.
#[derive(Debug, Clone)]
pub struct RuntimeError {
    msg: String,
}

impl RuntimeError {
    /// Create a new error.
    pub fn new<T>(msg: T) -> Self
    where
        T: ToString,
    {
        Self {
            msg: msg.to_string(),
        }
    }
}

impl Error for RuntimeError {}

impl Display for RuntimeError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        f.write_str(&self.msg)
    }
}

/// Get slice of bytes representing a given object.
pub fn as_bytes<T: Sized>(val: &T) -> &[u8] {
    let ptr = val as *const T;
    let size = mem::size_of::<T>();
    unsafe { slice::from_raw_parts(ptr as *const u8, size) }
}

/// Convert a given slice of Sized type instances to a slice of bytes.
pub fn slice_as_bytes<T: Sized>(data: &[T]) -> &[u8] {
    let ptr = data.as_ptr();
    let size = mem::size_of::<T>();
    unsafe { slice::from_raw_parts(ptr as *const u8, size * data.len()) }
}

/// Convert a given typed pointer into a new vector (copying the data).
///
/// # Safety
/// The given pointer MUST point to an array that contains at least `len`
/// elements. Each element is expected to be of size T.
pub unsafe fn vec_from_raw_parts<T: Clone>(ptr: *const T, len: usize) -> Vec<T> {
    slice::from_raw_parts(ptr, len).to_vec()
}

/// Convert a given C-string pointer to a new instance of String.
///
/// # Safety
/// The given pointer MUST point to a NULL terminated C string.
pub unsafe fn cstr_to_string(ptr: *const i8) -> String {
    let cstr = CStr::from_ptr(ptr as *const _);
    let slice = String::from_utf8_lossy(cstr.to_bytes());
    slice.to_string()
}

/// Unwrap a given result or log an error with a given severity and return None.
pub fn result_or_log<L, T, E, M>(
    logger: &mut L,
    severity: Severity,
    msg: M,
    res: Result<T, E>,
) -> Option<T>
where
    E: Error + Debug,
    L: Logger,
    M: Display,
{
    match res {
        Err(err) => {
            log!(logger, severity, "{} ({})", msg, err);
            None
        }
        Ok(res) => Some(res),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::logger::*;
    use std::ffi::CString;
    use std::fmt::Arguments;

    /// This logger does nothing but holds the severity level.
    #[derive(Debug, Copy, Clone)]
    pub struct DummyLogger {
        level: Severity,
    }

    impl DummyLogger {
        /// Create a new dummy logger.
        pub fn new() -> Self {
            Self {
                level: Severity::INFO,
            }
        }
    }

    impl Logger for DummyLogger {
        fn log(&mut self, _: &str, _: u32, _: Severity, _: Arguments) {}

        fn set_level(&mut self, s: Severity) {
            self.level = s;
        }

        fn get_level(&self) -> Severity {
            self.level
        }
    }

    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    #[repr(packed)]
    struct TestType {
        b1: u8,
        b2: u8,
    }

    #[test]
    fn test_vec_from_raw_parts() {
        let val = TestType { b1: 1, b2: 2 };
        let vec = vec![val, val];
        let ptr = vec.as_ptr();
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
    fn test_result_or_log() {
        let mut logger = DummyLogger::new();

        assert_eq!(
            Some(1),
            result_or_log::<DummyLogger, i32, RuntimeError, &'static str>(
                &mut logger,
                Severity::WARN,
                "",
                Ok(1)
            )
        );

        assert_eq!(
            None,
            result_or_log::<DummyLogger, i32, RuntimeError, &'static str>(
                &mut logger,
                Severity::WARN,
                "",
                Err(RuntimeError::new("foo"))
            )
        );
    }
}
