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
use std::result;

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

/// URL parse error.
#[derive(Debug, Clone)]
pub struct UrlParseError {
    msg: String,
}

impl Error for UrlParseError {
    fn description(&self) -> &str {
        &self.msg
    }
}

impl Display for UrlParseError {
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        f.write_str(self.description())
    }
}

impl<'a> From<&'a str> for UrlParseError {
    fn from(msg: &'a str) -> UrlParseError {
        UrlParseError { msg: msg.to_string() }
    }
}

/// Result alias.
pub type Result<T> = result::Result<T, UrlParseError>;

/// Simple URL parser.
#[derive(Clone)]
pub struct Url {
    serialized: String,
    hier:       usize,
    netloc:     usize,
    username:   Option<usize>,
    password:   Option<usize>,
    portpos:    Option<usize>,
    port:       Option<u16>,
    path:       Option<usize>,
    query:      Option<usize>,
    fragment:   Option<usize>,
}

impl Url {
    /// Initialize all URL fields.
    fn init(&mut self) -> Result<()> {
        if let Some(delim) = self.serialized.find(':') {
            self.process_hierarchy(delim + 1)
        } else {
            Err(UrlParseError::from("invalid URL"))
        }
    }

    /// Process the hierarchy part.
    fn process_hierarchy(&mut self, start: usize) -> Result<()> {
        self.hier = start;

        if self.serialized[start..].starts_with("//") {
            let authority = start + 3;
            let path = self.serialized[authority..].find('/');
            let end = path.unwrap_or(self.serialized.len());

            self.process_authority(authority, end)?;

            if let Some(path) = path {
                self.process_path(path);
            }

            Ok(())
        } else {
            Err(UrlParseError::from("invalid URL"))
        }
    }

    /// Process the authority part.
    fn process_authority(&mut self, start: usize, end: usize) -> Result<()> {
        if let Some(delim) = self.serialized[start..end].rfind('@') {
            self.process_user_info(start, delim);

            self.netloc = delim + 1;
        } else {
            self.netloc = start;
        }

        let netloc = &self.serialized[self.netloc..end];

        if !netloc.ends_with(']') {
            if let Some(delim) = netloc.rfind(':') {
                let ppos = delim + 1;
                let port = u16::from_str(&netloc[ppos..])
                    .map_err(|_| UrlParseError::from("invalid port"))?;

                self.portpos = Some(ppos);
                self.port    = Some(port);
            }
        }

        Ok(())
    }

    /// Process user info.
    fn process_user_info(&mut self, start: usize, end: usize) {
        let uinfo = &self.serialized[start..end];

        self.username = Some(start);

        if let Some(delim) = uinfo.find(':') {
            self.password = Some(delim + 1);
        }
    }

    /// Process the path part and everything that follows it.
    fn process_path(&mut self, start: usize) {
        let path = &self.serialized[start..];

        self.path = Some(start);

        if let Some(delim) = path.rfind('#') {
            self.fragment = Some(delim + 1);
        }

        let end = self.fragment.map(|f| f - 1)
            .unwrap_or(self.serialized.len());

        let path = &self.serialized[start..end];

        if let Some(delim) = path.rfind('?') {
            self.query = Some(delim + 1);
        }
    }

    /// Get URL scheme.
    pub fn scheme(&self) -> &str {
        &self.serialized[..self.hier-1]
    }

    /// Get username.
    pub fn username(&self) -> Option<&str> {
        if let Some(uname_pos) = self.username {
            if let Some(pwd_pos) = self.password {
                Some(&self.serialized[uname_pos..pwd_pos-1])
            } else {
                Some(&self.serialized[uname_pos..self.netloc-1])
            }
        } else {
            None
        }
    }

    /// Get password.
    pub fn password(&self) -> Option<&str> {
        if let Some(pwd_pos) = self.password {
            Some(&self.serialized[pwd_pos..self.netloc-1])
        } else {
            None
        }
    }

    /// Get host.
    pub fn host(&self) -> &str {
        if let Some(portpos) = self.portpos {
            &self.serialized[self.netloc..portpos-1]
        } else if let Some(path) = self.path {
            &self.serialized[self.netloc..path]
        } else {
            &self.serialized[self.netloc..]
        }
    }

    /// Get port.
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Get path.
    pub fn path(&self) -> &str {
        if let Some(path) = self.path {
            if let Some(query) = self.query {
                &self.serialized[path..query-1]
            } else if let Some(fragment) = self.fragment {
                &self.serialized[path..fragment-1]
            } else {
                &self.serialized[path..]
            }
        } else {
            "/"
        }
    }

    /// Get query.
    pub fn query(&self) -> Option<&str> {
        if let Some(query) = self.query {
            if let Some(fragment) = self.fragment {
                Some(&self.serialized[query..fragment-1])
            } else {
                Some(&self.serialized[query..])
            }
        } else {
            None
        }
    }

    /// Get fragment.
    pub fn fragment(&self) -> Option<&str> {
        if let Some(fragment) = self.fragment {
            Some(&self.serialized[fragment..])
        } else {
            None
        }
    }
}

impl AsRef<str> for Url {
    fn as_ref(&self) -> &str {
        &self.serialized
    }
}

impl Display for Url {
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        f.write_str(&self.serialized)
    }
}

impl FromStr for Url {
    type Err = UrlParseError;

    fn from_str(s: &str) -> Result<Url> {
        let mut url = Url {
            serialized: s.to_string(),
            hier:       0,
            netloc:     0,
            username:   None,
            password:   None,
            portpos:    None,
            port:       None,
            path:       None,
            query:      None,
            fragment:   None,
        };

        url.init()?;

        Ok(url)
    }
}
