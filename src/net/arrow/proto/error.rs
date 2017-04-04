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

/// Arrow Client error.
#[derive(Debug, Clone)]
pub struct ArrowError {
    msg:  String,
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
