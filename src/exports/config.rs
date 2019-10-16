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

use std::slice;

use std::ffi::CString;
use std::sync::{Arc, Mutex};

use libc::{c_char, c_int, c_void};

use crate::config::{Config, ConfigBuilder};
use crate::net::raw::ether::MacAddr;
use crate::utils::logger::{BoxLogger, Logger, Severity};

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
}

impl CallbackLoggerContext {
    /// Create a new context.
    fn new(callback: LogCallback, opaque: *mut c_void) -> Self {
        Self { callback, opaque }
    }

    /// Log message.
    fn log(&self, file: &str, line: u32, severity: Severity, msg: &str) {
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
/// be thread safe.
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
    fn log(&mut self, file: &str, line: u32, severity: Severity, msg: &str) {
        self.context.lock().unwrap().log(file, line, severity, msg)
    }

    fn set_level(&mut self, _: Severity) {}

    fn get_level(&self) -> Severity {
        Severity::DEBUG
    }
}

/// Create a new Arrow client config.
#[no_mangle]
pub extern "C" fn ac__config__new() -> *mut ConfigBuilder {
    Box::into_raw(Box::new(Config::builder()))
}

/// Free the config.
#[no_mangle]
pub extern "C" fn ac__config__free(config: *mut ConfigBuilder) {
    unsafe { Box::from_raw(config) };
}

/// Set log callback.
#[no_mangle]
pub extern "C" fn ac__config__set_log_callback(
    config: *mut ConfigBuilder,
    callback: LogCallback,
    opaque: *mut c_void,
) {
    let builder = unsafe { &mut *config };

    builder.logger(BoxLogger::new(CallbackLogger::new(callback, opaque)));
}

/// Set MAC address. The `mac_address` parameter is expected to be a an array
/// of six bytes or NULL.
#[no_mangle]
pub extern "C" fn ac__config__set_mac_address(config: *mut ConfigBuilder, mac_address: *const u8) {
    let mac_address = unsafe {
        if mac_address.is_null() {
            None
        } else {
            Some(slice::from_raw_parts(mac_address, 6))
        }
    };

    let mac_address = mac_address.map(MacAddr::from_slice);

    let builder = unsafe { &mut *config };

    builder.mac_address(mac_address);
}

/// Enable/disable diagnostic mode.
#[no_mangle]
pub extern "C" fn ac__config__set_diagnostic_mode(config: *mut ConfigBuilder, enabled: c_int) {
    let builder = unsafe { &mut *config };

    builder.diagnostic_mode(enabled != 0);
}

/// Enable/disable automatic service discovery.
#[no_mangle]
pub extern "C" fn ac__config__set_discovery(config: *mut ConfigBuilder, enabled: c_int) {
    let builder = unsafe { &mut *config };

    builder.discovery(enabled != 0);
}

/// Enable/disable verbose mode.
#[no_mangle]
pub extern "C" fn ac__config__set_verbose(config: *mut ConfigBuilder, enabled: c_int) {
    let builder = unsafe { &mut *config };

    builder.verbose(enabled != 0);
}
