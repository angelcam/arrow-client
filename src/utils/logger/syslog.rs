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

//! Syslog definitions.

use std::ptr;

use std::ffi::CString;
use std::sync::Once;

use libc::{c_char, c_int, c_void};

use crate::utils::logger::{Logger, Severity};

const LOG_PID: c_int = 0x01;
const LOG_CONS: c_int = 0x02;

const LOG_USER: c_int = 0x08;

const LOG_ERR: c_int = 3;
const LOG_WARNING: c_int = 4;
const LOG_INFO: c_int = 6;
const LOG_DEBUG: c_int = 7;

static SYSLOG_INIT: Once = Once::new();

#[link(name = "c")]
extern "C" {
    fn openlog(ident: *const c_char, option: c_int, facility: c_int) -> c_void;
    fn syslog(priority: c_int, format: *const c_char, ...) -> c_void;
}

/// Syslog logger structure.
#[derive(Debug, Clone)]
pub struct Syslog {
    level: Severity,
}

impl Syslog {
    /// Create a new syslog logger with log level set to INFO.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Syslog {
    fn default() -> Self {
        SYSLOG_INIT.call_once(|| unsafe {
            openlog(ptr::null(), LOG_CONS | LOG_PID, LOG_USER);
        });

        Self {
            level: Severity::INFO,
        }
    }
}

impl Logger for Syslog {
    fn log(&mut self, file: &str, line: u32, s: Severity, msg: &str) {
        let msg = format!("[{}:{}] {}", file, line, msg);
        let cstr_fmt = CString::new("%s").unwrap();
        let cstr_msg = CString::new(msg).unwrap();
        let fmt_ptr = cstr_fmt.as_ptr() as *const c_char;
        let msg_ptr = cstr_msg.as_ptr() as *const c_char;

        if s >= self.level {
            unsafe {
                match s {
                    Severity::DEBUG => syslog(LOG_DEBUG, fmt_ptr, msg_ptr),
                    Severity::INFO => syslog(LOG_INFO, fmt_ptr, msg_ptr),
                    Severity::WARN => syslog(LOG_WARNING, fmt_ptr, msg_ptr),
                    Severity::ERROR => syslog(LOG_ERR, fmt_ptr, msg_ptr),
                }
            };
        }
    }

    fn set_level(&mut self, s: Severity) {
        self.level = s;
    }

    fn get_level(&self) -> Severity {
        self.level
    }
}
