// Copyright 2016 click2stream, Inc.
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

//! stderr logger definitions.

use std;
use std::io::{Stderr, Write};

use time;

use crate::utils::logger::{Logger, Severity};

/// stderr logger structure.
pub struct StderrLogger {
    level: Severity,
    stderr: Stderr,
    pretty: bool,
}

/// Create a new stderr logger with log level set to INFO.
pub fn new() -> StderrLogger {
    StderrLogger {
        level: Severity::INFO,
        stderr: std::io::stderr(),
        pretty: false,
    }
}

/// Create a new stderr logger with color formatted messages.
pub fn new_pretty() -> StderrLogger {
    StderrLogger {
        level: Severity::INFO,
        stderr: std::io::stderr(),
        pretty: true,
    }
}

impl Clone for StderrLogger {
    fn clone(&self) -> Self {
        Self {
            level: self.level,
            stderr: std::io::stderr(),
            pretty: self.pretty,
        }
    }
}

impl Logger for StderrLogger {
    fn log(&mut self, file: &str, line: u32, s: Severity, msg: &str) {
        let t = time::strftime("%F %T", &time::now()).unwrap();

        let severity = match s {
            Severity::DEBUG => "DEBUG",
            Severity::INFO => "INFO",
            Severity::WARN => "WARNING",
            Severity::ERROR => "ERROR",
        };

        let color = match s {
            Severity::DEBUG => "1;30",
            Severity::INFO => "0;37",
            Severity::WARN => "0;33",
            Severity::ERROR => "0;31",
        };

        if s >= self.level {
            if self.pretty {
                writeln!(
                    &mut self.stderr,
                    "\x1b[{}m{} {:<7} [{}:{}] {}\x1b[m",
                    color, t, severity, file, line, msg
                )
                .unwrap();
            } else {
                writeln!(
                    &mut self.stderr,
                    "{} {:<7} [{}:{}] {}",
                    t, severity, file, line, msg
                )
                .unwrap();
            }
        }
    }

    fn set_level(&mut self, s: Severity) {
        self.level = s;
    }

    fn get_level(&self) -> Severity {
        self.level
    }
}
