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

use std::error::Error;
use std::fmt::{Display, Formatter};

use json;

use json::JsonValue;

/// JSON parse error.
#[derive(Debug, Clone)]
pub struct ParseError {
    msg: String,
}

impl Error for ParseError {
    fn description(&self) -> &str {
        &self.msg
    }
}

impl Display for ParseError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        f.write_str(&self.msg)
    }
}

impl From<String> for ParseError {
    fn from(msg: String) -> ParseError {
        ParseError { msg: msg }
    }
}

impl<'a> From<&'a str> for ParseError {
    fn from(msg: &'a str) -> ParseError {
        ParseError::from(msg.to_string())
    }
}

impl From<json::Error> for ParseError {
    fn from(err: json::Error) -> ParseError {
        ParseError::from(err.description())
    }
}

/// Common trait for objects that can be constructed from JSON.
pub trait FromJson : Sized {
    /// Parse object from JSON.
    fn from_json(value: JsonValue) -> Result<Self, ParseError>;
}

/// Common trait for objects that can be represented as JSON.
pub trait ToJson {
    /// Get JSON representation of the object.
    fn to_json(&self) -> JsonValue;
}
