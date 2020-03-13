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

use std::fmt;
use std::io;
use std::result;

use std::error::Error;
use std::fmt::{Display, Formatter};

use crate::net::arrow::proto::error::DecodeError;
use crate::net::tls::TlsError;
use crate::utils::RuntimeError;

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
    msg: String,
}

impl ArrowError {
    /// Create a new ArrowError with a given ErrorKind.
    fn new<T>(kind: ErrorKind, msg: T) -> Self
    where
        T: ToString,
    {
        Self {
            kind,
            msg: msg.to_string(),
        }
    }

    /// Create a new connection error.
    pub fn connection_error<T>(msg: T) -> Self
    where
        T: ToString,
    {
        Self::new(ErrorKind::ConnectionError, msg)
    }

    /// Create a new unsupported protocol version error.
    pub fn unsupported_protocol_version<T>(msg: T) -> Self
    where
        T: ToString,
    {
        Self::new(ErrorKind::UnsupportedProtocolVersion, msg)
    }

    /// Create a new unauthorized error.
    pub fn unauthorized<T>(msg: T) -> Self
    where
        T: ToString,
    {
        Self::new(ErrorKind::Unauthorized, msg)
    }

    /// Create a new Arrow Server error.
    pub fn arrow_server_error<T>(msg: T) -> Self
    where
        T: ToString,
    {
        Self::new(ErrorKind::ArrowServerError, msg)
    }

    /// Create another error.
    pub fn other<T>(msg: T) -> Self
    where
        T: ToString,
    {
        Self::new(ErrorKind::Other, msg)
    }

    /// Get error kind.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl Error for ArrowError {}

impl Display for ArrowError {
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        f.write_str(&self.msg)
    }
}

impl From<String> for ArrowError {
    fn from(msg: String) -> Self {
        Self {
            kind: ErrorKind::Other,
            msg,
        }
    }
}

impl<'a> From<&'a str> for ArrowError {
    fn from(msg: &'a str) -> Self {
        Self::from(msg.to_string())
    }
}

impl From<io::Error> for ArrowError {
    fn from(err: io::Error) -> Self {
        Self::other(format!("IO error: {}", err))
    }
}

impl From<DecodeError> for ArrowError {
    fn from(err: DecodeError) -> Self {
        Self::other(format!("Arrow Message decoding error: {}", err))
    }
}

impl From<ConnectionError> for ArrowError {
    fn from(err: ConnectionError) -> Self {
        Self::other(format!("connection error: {}", err))
    }
}

impl From<RuntimeError> for ArrowError {
    fn from(err: RuntimeError) -> Self {
        Self::other(format!("runtime error: {}", err))
    }
}

impl From<TlsError> for ArrowError {
    fn from(err: TlsError) -> Self {
        Self::other(format!("TLS error: {}", err))
    }
}

/// Connection error.
#[derive(Debug, Clone)]
pub struct ConnectionError {
    msg: String,
}

impl ConnectionError {
    /// Create a new error.
    pub fn new<T>(msg: T) -> Self
    where
        T: ToString,
    {
        Self {
            msg: msg.to_string(),
        }
    }
}

impl Error for ConnectionError {}

impl Display for ConnectionError {
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        f.write_str(&self.msg)
    }
}

impl From<io::Error> for ConnectionError {
    fn from(err: io::Error) -> Self {
        Self::new(format!("IO error: {}", err))
    }
}
