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

//! Logger definitions.

macro_rules! log {
    ($logger:expr, $severity:expr, $( $arg:tt )*) => {
        $logger.log(file!(), line!(), $severity, format_args!($($arg)*))
    };
}

macro_rules! log_debug {
    ($logger:expr, $( $arg:tt )*) => {
        $logger.debug(file!(), line!(), format_args!($($arg)*))
    };
}

macro_rules! log_info {
    ($logger:expr, $( $arg:tt )*) => {
        $logger.info(file!(), line!(), format_args!($($arg)*))
    };
}

macro_rules! log_warn {
    ($logger:expr, $( $arg:tt )*) => {
        $logger.warn(file!(), line!(), format_args!($($arg)*))
    };
}

pub mod file;
pub mod stderr;
pub mod syslog;

use std::fmt::Arguments;

/// Log message severity.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum Severity {
    DEBUG = 0,
    INFO = 1,
    WARN = 2,
    ERROR = 3,
}

const DEBUG: Severity = Severity::DEBUG;
const INFO: Severity = Severity::INFO;
const WARN: Severity = Severity::WARN;
const ERROR: Severity = Severity::ERROR;

/// Common trait for application loggers.
pub trait Logger: Send {
    /// Log a given message with a given severity.
    fn log(&mut self, file: &str, line: u32, s: Severity, msg: Arguments);

    /// Set minimum log level.
    ///
    /// Messages with lover level will be discarded.
    fn set_level(&mut self, s: Severity);

    /// Get minimum log level.
    fn get_level(&self) -> Severity;

    /// Log a given debug message.
    fn debug(&mut self, file: &str, line: u32, msg: Arguments) {
        self.log(file, line, DEBUG, msg)
    }

    /// Log a given info message.
    fn info(&mut self, file: &str, line: u32, msg: Arguments) {
        self.log(file, line, INFO, msg)
    }

    /// Log a given warning message.
    fn warn(&mut self, file: &str, line: u32, msg: Arguments) {
        self.log(file, line, WARN, msg)
    }

    /// Log a given error message.
    fn error(&mut self, file: &str, line: u32, msg: Arguments) {
        self.log(file, line, ERROR, msg)
    }
}

/// Helper trait for implementing Clone to the BoxLogger.
pub trait CloneableLogger: Logger {
    /// Clone as trait object.
    fn clone(&self) -> Box<dyn CloneableLogger + Send + Sync>;
}

impl<T> CloneableLogger for T
where
    T: 'static + Logger + Clone + Send + Sync,
{
    fn clone(&self) -> Box<dyn CloneableLogger + Send + Sync> {
        Box::new(<Self as Clone>::clone(self))
    }
}

/// Abstraction from a concrete logger type.
pub struct BoxLogger {
    logger: Box<dyn CloneableLogger + Send + Sync>,
}

impl BoxLogger {
    /// Create a new boxed logger.
    pub fn new<L: 'static + CloneableLogger + Send + Sync>(logger: L) -> Self {
        Self {
            logger: Box::new(logger),
        }
    }
}

impl Clone for BoxLogger {
    fn clone(&self) -> Self {
        let logger = self.logger.as_ref().clone();

        Self { logger }
    }
}

impl Logger for BoxLogger {
    fn log(&mut self, file: &str, line: u32, s: Severity, msg: Arguments) {
        self.logger.log(file, line, s, msg)
    }

    fn set_level(&mut self, s: Severity) {
        self.logger.set_level(s);
    }

    fn get_level(&self) -> Severity {
        self.logger.get_level()
    }
}

/// A dummy logger that will drop everything.
#[derive(Copy, Clone)]
pub struct DummyLogger {
    level: Severity,
}

impl Default for DummyLogger {
    fn default() -> Self {
        Self {
            level: Severity::DEBUG,
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

#[cfg(test)]
mod tests {
    use super::*;

    struct TestLogger {
        last_severity: Severity,
    }

    impl Logger for TestLogger {
        fn log(&mut self, _: &str, _: u32, s: Severity, _: Arguments) {
            self.last_severity = s;
        }

        fn set_level(&mut self, _: Severity) {}
        fn get_level(&self) -> Severity {
            Severity::DEBUG
        }
    }

    #[test]
    fn test_logger() {
        let mut logger = TestLogger {
            last_severity: Severity::DEBUG,
        };

        log_warn!(logger, "msg");
        assert_eq!(Severity::WARN, logger.last_severity);
        log_info!(logger, "msg");
        assert_eq!(Severity::INFO, logger.last_severity);
        log_debug!(logger, "msg");
        assert_eq!(Severity::DEBUG, logger.last_severity);
    }
}
