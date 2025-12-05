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

use std::{
    io::{Stderr, Write},
    sync::Mutex,
};

use log::{Level, Log, Metadata, Record};

use crate::utils::logger::LogTimeFormatter;

/// Stderr logger.
pub struct StderrLogger {
    stderr: Mutex<Stderr>,
    pretty: bool,
}

impl StderrLogger {
    /// Create a new stderr logger.
    pub fn new(pretty: bool) -> Self {
        Self {
            stderr: Mutex::new(std::io::stderr()),
            pretty,
        }
    }
}

impl Log for StderrLogger {
    fn enabled(&self, _: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let file = record.file().unwrap_or("-");
        let line = record.line().unwrap_or(0);

        let args = record.args();

        let (level, color) = match record.level() {
            Level::Trace => ("TRACE", "1;30"),
            Level::Debug => ("DEBUG", "1;30"),
            Level::Info => ("INFO", "0;37"),
            Level::Warn => ("WARNING", "0;33"),
            Level::Error => ("ERROR", "0;31"),
        };

        let mut time_formatter = LogTimeFormatter::new();

        let t = time_formatter.format();

        let mut stderr = self.stderr.lock().unwrap();

        if self.pretty {
            let _ = writeln!(
                stderr,
                "\x1b[{color}m{t} {level:<7} [{file}:{line}] {args}\x1b[m"
            );
        } else {
            let _ = writeln!(stderr, "{t} {level:<7} [{file}:{line}] {args}");
        }
    }

    fn flush(&self) {
        let _ = self.stderr.lock().unwrap().flush();
    }
}
