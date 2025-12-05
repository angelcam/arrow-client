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

use std::{ffi::CString, sync::Once};

use libc::{LOG_CONS, LOG_PID, LOG_USER};
use log::{Level, Log, Metadata, Record};

static SYSLOG_INIT: Once = Once::new();

/// Syslog logger.
pub struct Syslog(());

impl Syslog {
    /// Create a new syslog logger.
    pub fn new() -> Self {
        SYSLOG_INIT.call_once(|| unsafe {
            libc::openlog(std::ptr::null(), LOG_CONS | LOG_PID, LOG_USER);
        });

        Self(())
    }
}

impl Default for Syslog {
    fn default() -> Self {
        Self::new()
    }
}

impl Log for Syslog {
    fn enabled(&self, _: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let file = record.file().unwrap_or("-");
        let line = record.line().unwrap_or(0);

        let args = record.args();

        let priority = match record.level() {
            Level::Trace => libc::LOG_DEBUG,
            Level::Debug => libc::LOG_DEBUG,
            Level::Info => libc::LOG_INFO,
            Level::Warn => libc::LOG_WARNING,
            Level::Error => libc::LOG_ERR,
        };

        let msg = format!("[{file}:{line}] {args}")
            .replace('\0', "\\0")
            .into();

        // SAFETY: We just replaced all 0 bytes.
        let msg = unsafe { CString::from_vec_unchecked(msg) };

        let fmt = b"%s\0";

        let fmt_ptr = fmt.as_ptr() as *const libc::c_char;
        let msg_ptr = msg.as_ptr() as *const libc::c_char;

        unsafe {
            libc::syslog(priority, fmt_ptr, msg_ptr);
        }
    }

    fn flush(&self) {}
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use log::{Level, Log, Record};

    use super::Syslog;

    #[test]
    fn test_syslog_nul_character() {
        // Check that there is no panic on attempt to log the nul-character.
        let record = Record::builder()
            .args(format_args!("nul character: \0"))
            .level(Level::Warn)
            .file(Some("test.rs"))
            .line(Some(42))
            .build();

        let logger = Syslog::new();

        logger.log(&record);
    }
}
