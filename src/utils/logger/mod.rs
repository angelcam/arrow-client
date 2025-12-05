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

mod file;
mod stderr;

#[cfg(not(target_os = "windows"))]
mod syslog;

use std::mem::MaybeUninit;

pub use self::{file::FileLogger, stderr::StderrLogger};

#[cfg(not(target_os = "windows"))]
pub use self::syslog::Syslog;

/// Formatter for log timestamps.
struct LogTimeFormatter {
    buf: MaybeUninit<[u8; Self::BUF_SIZE]>,
}

impl LogTimeFormatter {
    const BUF_SIZE: usize = 32;

    /// Create a new log time formatter.
    fn new() -> Self {
        Self {
            buf: MaybeUninit::uninit(),
        }
    }

    /// Format the current time as a string.
    fn format(&mut self) -> &str {
        let buf = self.format_as_bytes();

        // SAFETY: The buffer is always valid UTF-8 as it is produced by
        //   strftime.
        unsafe { std::str::from_utf8_unchecked(buf) }
    }

    /// Format the current time.
    fn format_as_bytes(&mut self) -> &[u8] {
        unsafe {
            let mut t: libc::time_t = 0;

            if libc::time(&mut t) == (-1 as libc::time_t) {
                return &[];
            }

            let mut tm = MaybeUninit::<libc::tm>::uninit();

            let res = libc::localtime_r(&t, tm.as_mut_ptr());

            if res.is_null() {
                return &[];
            }

            let fmt = b"%F %T\0";

            let max = Self::BUF_SIZE as libc::size_t;
            let buf = self.buf.as_mut_ptr() as *mut libc::c_char;
            let fmt = fmt.as_ptr() as *const libc::c_char;

            let len = libc::strftime(buf, max, fmt, tm.as_ptr());

            &self.buf.assume_init_ref()[..len]
        }
    }
}
