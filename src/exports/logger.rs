// Copyright 2019 Angelcam, Inc.
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

use std::ffi::CString;
use std::fmt::Arguments;
use std::sync::{Arc, Mutex};

use libc::{c_char, c_int, c_void, size_t};

use crate::utils::logger::file::FileLogger;
use crate::utils::logger::stderr::StderrLogger;

#[cfg(not(target_os = "windows"))]
use crate::utils::logger::syslog::Syslog;

use crate::utils::logger::{BoxLogger, Logger, Severity};

use crate::exports::cstr_to_str;

/// Type alias for log callbacks.
type LogCallback = extern "C" fn(
    opaque: *mut c_void,
    file: *const c_char,
    line: u32,
    severity: u32,
    msg: *const c_char,
);

/// Internal context for callback-based loggers.
struct CallbackLoggerContext {
    callback: LogCallback,
    opaque: *mut c_void,
    level: Severity,
}

impl CallbackLoggerContext {
    /// Create a new context.
    fn new(callback: LogCallback, opaque: *mut c_void) -> Self {
        Self {
            callback,
            opaque,
            level: Severity::INFO,
        }
    }

    /// Log message.
    fn log(&self, file: &str, line: u32, severity: Severity, msg: Arguments) {
        if severity < self.level {
            return;
        }

        let msg = std::fmt::format(msg);

        let file = CString::new(file).unwrap();
        let msg = CString::new(msg).unwrap();

        (self.callback)(
            self.opaque,
            file.as_ptr() as _,
            line,
            severity as u32,
            msg.as_ptr() as _,
        );
    }
}

unsafe impl Send for CallbackLoggerContext {}

/// Callback-based logger. The callback does not have to be thread-safe. The
/// logger will handle all necessary locking. However, the given opaque MUST
/// be safe to be transferred across thread boundary.
#[derive(Clone)]
struct CallbackLogger {
    context: Arc<Mutex<CallbackLoggerContext>>,
}

impl CallbackLogger {
    /// Create a new logger.
    fn new(callback: LogCallback, opaque: *mut c_void) -> Self {
        Self {
            context: Arc::new(Mutex::new(CallbackLoggerContext::new(callback, opaque))),
        }
    }
}

impl Logger for CallbackLogger {
    fn log(&mut self, file: &str, line: u32, severity: Severity, msg: Arguments) {
        self.context.lock().unwrap().log(file, line, severity, msg)
    }

    fn set_level(&mut self, level: Severity) {
        let mut context = self.context.lock().unwrap();

        context.level = level;
    }

    fn get_level(&self) -> Severity {
        let context = self.context.lock().unwrap();

        context.level
    }
}

/// Create a new logger using a given custom log callback.
#[no_mangle]
pub unsafe extern "C" fn ac__logger__custom(
    callback: LogCallback,
    opaque: *mut c_void,
) -> *mut BoxLogger {
    Box::into_raw(Box::new(BoxLogger::new(CallbackLogger::new(
        callback, opaque,
    ))))
}

/// Create a new syslog logger.
#[cfg(not(target_os = "windows"))]
#[no_mangle]
pub unsafe extern "C" fn ac__logger__syslog() -> *mut BoxLogger {
    Box::into_raw(Box::new(BoxLogger::new(Syslog::new())))
}

/// Create a new stderr logger.
#[no_mangle]
pub unsafe extern "C" fn ac__logger__stderr(pretty: c_int) -> *mut BoxLogger {
    Box::into_raw(Box::new(BoxLogger::new(StderrLogger::new(pretty != 0))))
}

/// Create a new file logger.
#[no_mangle]
pub unsafe extern "C" fn ac__logger__file(
    path: *const c_char,
    limit: size_t,
    rotations: size_t,
) -> *mut BoxLogger {
    let path = cstr_to_str(path);

    let logger = FileLogger::new(path, limit as _, rotations as _);

    match logger {
        Ok(logger) => Box::into_raw(Box::new(BoxLogger::new(logger))),
        Err(_) => ptr::null_mut(),
    }
}

/// Clone a given logger.
#[no_mangle]
pub unsafe extern "C" fn ac__logger__clone(logger: *const BoxLogger) -> *mut BoxLogger {
    let logger = &*logger;

    Box::into_raw(Box::new(logger.clone()))
}

/// Free a give logger.
#[no_mangle]
pub unsafe extern "C" fn ac__logger__free(logger: *mut BoxLogger) {
    Box::from_raw(logger);
}
