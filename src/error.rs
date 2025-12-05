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
    borrow::Cow,
    fmt::{self, Display, Formatter},
    io,
};

/// Error type.
#[derive(Debug)]
pub struct Error {
    msg: Cow<'static, str>,
    cause: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl Error {
    /// Create a new error with a given message.
    pub fn from_msg<T>(msg: T) -> Self
    where
        T: Into<String>,
    {
        Self {
            msg: Cow::Owned(msg.into()),
            cause: None,
        }
    }

    /// Create a new error with a given message.
    pub const fn from_static_msg(msg: &'static str) -> Self {
        Self {
            msg: Cow::Borrowed(msg),
            cause: None,
        }
    }

    /// Create a new error with a given message and cause.
    pub fn from_msg_and_cause<T, E>(msg: T, cause: E) -> Self
    where
        T: Into<String>,
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            msg: Cow::Owned(msg.into()),
            cause: Some(cause.into()),
        }
    }

    /// Create a new error with a given message and cause.
    pub fn from_static_msg_and_cause<E>(msg: &'static str, cause: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            msg: Cow::Borrowed(msg),
            cause: Some(cause.into()),
        }
    }

    /// Create a new error from another error.
    pub fn from_other<E>(cause: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            msg: Cow::Borrowed(""),
            cause: Some(cause.into()),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(cause) = self.cause.as_ref() {
            if self.msg.is_empty() {
                Display::fmt(cause, f)
            } else {
                write!(f, "{}: {}", self.msg, cause)
            }
        } else if self.msg.is_empty() {
            f.write_str("unknown error")
        } else {
            f.write_str(&self.msg)
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause.as_ref().map(|cause| &**cause as _)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::from_static_msg_and_cause("IO error", err)
    }
}
