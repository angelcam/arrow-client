// Copyright 2017 click2stream, Inc.
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

use std::io;
use std::fmt;
use std::result;

use std::error::Error;
use std::fmt::{Display, Formatter};

use tokio_timer::{TimerError, TimeoutError};

/// Message decoding error.
#[derive(Debug, Clone)]
pub struct DecodeError {
    /// Error message.
    msg: String,
}

impl Error for DecodeError {
    /// Get error description.
    fn description(&self) -> &str {
        &self.msg
    }
}

impl Display for DecodeError {
    /// Format error message.
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        f.write_str(&self.msg)
    }
}

impl From<String> for DecodeError {
    /// Create a new DecodeError from a given error string.
    fn from(msg: String) -> DecodeError {
        DecodeError {
            msg: msg
        }
    }
}

impl<'a> From<&'a str> for DecodeError {
    /// Create a new DecodeError from a given error string.
    fn from(msg: &'a str) -> DecodeError {
        DecodeError::from(msg.to_string())
    }
}

/// Arrow error kinds.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ErrorKind {
    /// A problem with connecting to Arrow Server.
    ConnectionError,
    /// Arrow Server does not support this version of Arrow Protocol.
    UnsupportedProtocolVersion,
    /// Arrow Server does not know this client.
    Unauthorized,
    /// An internal Arrow Server error.
    ArrowServerError,
    /// Unspecified error.
    Other,
}

/// Arrow Client error.
#[derive(Debug, Clone)]
pub struct ArrowError {
    kind: ErrorKind,
    msg:  String,
}

impl ArrowError {
    /// Create a new ArrowError with a given ErrorKind.
    fn new<T>(kind: ErrorKind, val: T) -> ArrowError
        where ArrowError: From<T> {
        let err = ArrowError::from(val);
        ArrowError {
            kind: kind,
            msg:  err.msg
        }
    }

    /// Create a new connection error.
    pub fn connection_error<T>(val: T) -> ArrowError
        where ArrowError: From<T> {
        ArrowError::new(ErrorKind::ConnectionError, val)
    }

    /// Create a new unsupported protocol version error.
    pub fn unsupported_protocol_version<T>(val: T) -> ArrowError
        where ArrowError: From<T> {
        ArrowError::new(ErrorKind::UnsupportedProtocolVersion, val)
    }

    /// Create a new unauthorized error.
    pub fn unauthorized<T>(val: T) -> ArrowError
        where ArrowError: From<T> {
        ArrowError::new(ErrorKind::Unauthorized, val)
    }

    /// Create a new Arrow Server error.
    pub fn arrow_server_error<T>(val: T) -> ArrowError
        where ArrowError: From<T> {
        ArrowError::new(ErrorKind::ArrowServerError, val)
    }

    /// Create another error.
    pub fn other<T>(val: T) -> ArrowError
        where ArrowError: From<T> {
        ArrowError::new(ErrorKind::Other, val)
    }

    /// Get error kind.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl Error for ArrowError {
    fn description(&self) -> &str {
        &self.msg
    }
}

impl Display for ArrowError {
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        f.write_str(&self.msg)
    }
}

impl From<String> for ArrowError {
    fn from(msg: String) -> ArrowError {
        ArrowError {
            kind: ErrorKind::Other,
            msg:  msg
        }
    }
}

impl<'a> From<&'a str> for ArrowError {
    fn from(msg: &'a str) -> ArrowError {
        ArrowError::from(msg.to_string())
    }
}

impl From<io::Error> for ArrowError {
    fn from(err: io::Error) -> ArrowError {
        ArrowError::from(format!("IO error: {}", err))
    }
}

impl From<DecodeError> for ArrowError {
    fn from(err: DecodeError) -> ArrowError {
        ArrowError::from(format!("Arrow Message decoding error: {}", err))
    }
}

impl From<TimerError> for ArrowError {
    fn from(err: TimerError) -> ArrowError {
        ArrowError::from(format!("timer error: {}", err))
    }
}

impl From<ConnectionError> for ArrowError {
    fn from(err: ConnectionError) -> ArrowError {
        ArrowError::from(format!("connection error: {}", err))
    }
}

/// Connection error.
#[derive(Debug, Clone)]
pub struct ConnectionError {
    msg:  String,
}

impl Error for ConnectionError {
    fn description(&self) -> &str {
        &self.msg
    }
}

impl Display for ConnectionError {
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        f.write_str(&self.msg)
    }
}

impl From<String> for ConnectionError {
    fn from(msg: String) -> ConnectionError {
        ConnectionError {
            msg:  msg
        }
    }
}

impl<'a> From<&'a str> for ConnectionError {
    fn from(msg: &'a str) -> ConnectionError {
        ConnectionError::from(msg.to_string())
    }
}

impl From<io::Error> for ConnectionError {
    fn from(err: io::Error) -> ConnectionError {
        ConnectionError::from(format!("IO error: {}", err))
    }
}

impl<T> From<TimeoutError<T>> for ConnectionError {
    fn from(err: TimeoutError<T>) -> ConnectionError {
        ConnectionError::from(format!("connection timeout: {}", err))
    }
}
