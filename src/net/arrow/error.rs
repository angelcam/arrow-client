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

//! Definitions of ArrowError which may be returned by Arrow client.

use std::io;
use std::fmt;
use std::result;

use std::error::Error;
use std::fmt::{Display, Formatter};

//use mio;

use openssl::ssl;

/// Try an IO operation (an error will be translated to the Arrow Connection
/// Error).
macro_rules! try_io {
    ($t:expr) => {
        match $t {
            Err(e) => return Err(ArrowError::connection_error(e)),
            Ok(ok) => ok
        }
    };
}

/// Try a service IO operation (an error will be translated to the Arrow
/// Service Connection Error).
macro_rules! try_svc_io {
    ($t:expr) => {
        match $t {
            Err(e) => return Err(ArrowError::service_connection_error(e)),
            Ok(ok) => ok
        }
    };
}

/// Works almost like the normal try! (an error will be translated to the Arrow
/// Error).
macro_rules! try_other {
    ($t:expr) => {
        match $t {
            Err(e) => return Err(ArrowError::other(e)),
            Ok(ok) => ok
        }
    };
}

/// Try an Arrow operation (i.e. only results returning the Arrow Error are
/// accepted.)
macro_rules! try_arr {
    ($t:expr) => {
        match $t {
            Err(e) => return Err(e),
            Ok(ok) => ok
        }
    };
}

/*// Type alias for Result with ArrowError.
pub type Result<T> = result::Result<T, ArrowError>;

/// Arrow error kinds.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ErrorKind {
    /// A problem with connecting to Arrow Server.
    ConnectionError,
    /// Arrow Server does not support this version of Arrow Protocol.
    UnsupportedProtocolVersion,
    /// Arrow Server does not know this client.
    Unauthorized,
    /// A service connection related error.
    ServiceConnectionError,
    /// An internal Arrow Server error.
    ArrowServerError,
    /// Unspecified error.
    Other,
}

/// Arrow error (it may be returned by Arrow client).
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

    /// Create a new service connection error.
    pub fn service_connection_error<T>(val: T) -> ArrowError
        where ArrowError: From<T> {
        ArrowError::new(ErrorKind::ServiceConnectionError, val)
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
    /// Get error description.
    fn description(&self) -> &str {
        &self.msg
    }
}

impl Display for ArrowError {
    /// Format error message.
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        f.write_str(&self.msg)
    }
}

impl From<String> for ArrowError {
    /// Create a new ArrowError from a given error string.
    fn from(msg: String) -> ArrowError {
        ArrowError {
            kind: ErrorKind::Other,
            msg:  msg
        }
    }
}

impl<'a> From<&'a str> for ArrowError {
    /// Create a new ArrowError from a given error string.
    fn from(msg: &'a str) -> ArrowError {
        ArrowError::from(msg.to_string())
    }
}

impl From<io::Error> for ArrowError {
    /// Create a new ArrowError from a given IO error.
    fn from(err: io::Error) -> ArrowError {
        ArrowError::from(format!("IO error: {}", err))
    }
}

impl From<mio::TimerError> for ArrowError {
    /// Create a new ArrowError for a given timer error.
    fn from(_: mio::TimerError) -> ArrowError {
        ArrowError::from("timer error")
    }
}

impl From<ssl::Error> for ArrowError {
    /// Create a new ArrowError from a given SSL error.
    fn from(err: ssl::Error) -> ArrowError {
        ArrowError::from(format!("OpenSSL error: {}", err))
    }
}*/
