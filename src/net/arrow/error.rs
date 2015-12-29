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

use mio::TimerError;

use openssl::ssl::error::{SslError, NonblockingSslError};

/// Type alias for Result with ArrowError.
pub type Result<T> = result::Result<T, ArrowError>;

/// Arrow error (it may be returned by Arrow client).
#[derive(Debug, Clone)]
pub struct ArrowError {
    msg: String,
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
        ArrowError { msg: msg }
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
        ArrowError::from(format!("IO error: {}", err.description()))
    }
}

impl From<TimerError> for ArrowError {
    /// Create a new ArrowError for a given timer error.
    fn from(_: TimerError) -> ArrowError {
        ArrowError::from("timer error")
    }
}

impl From<SslError> for ArrowError {
    /// Create a new ArrowError from a given SSL error.
    fn from(err: SslError) -> ArrowError {
        ArrowError::from(format!("OpenSSL error: {}", err.description()))
    }
}

impl From<NonblockingSslError> for ArrowError {
    /// Create a new ArrowError from a given SSL error.
    fn from(err: NonblockingSslError) -> ArrowError {
        ArrowError::from(format!("OpenSSL error: {}", err.description()))
    }
}
