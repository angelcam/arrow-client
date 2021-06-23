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

impl UrlParseError {
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

impl Error for UrlParseError {}

impl Display for UrlParseError {
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        f.write_str(&self.msg)
    }
}

/// Result alias.
pub type Result<T> = result::Result<T, UrlParseError>;

/// Simple URL parser.
#[derive(Clone)]
pub struct Url {
    serialized: String,
    hier: usize,
    netloc: usize,
    username: Option<usize>,
    password: Option<usize>,
    portpos: Option<usize>,
    port: Option<u16>,
    path: Option<usize>,
    query: Option<usize>,
    fragment: Option<usize>,
}

impl Url {
    /// Initialize all URL fields.
    fn init(&mut self) -> Result<()> {
        if let Some(delim) = self.serialized.find(':') {
            self.process_hierarchy(delim + 1)
        } else {
            Err(UrlParseError::new("invalid URL"))
        }
    }

    /// Process the hierarchy part.
    fn process_hierarchy(&mut self, start: usize) -> Result<()> {
        self.hier = start;

        if self.serialized[start..].starts_with("//") {
            let authority = start + 2;

            if let Some(pos) = self.serialized[authority..].find('/') {
                let path = authority + pos;

                self.process_authority(authority, path)?;
                self.process_path(path);
            } else {
                let authority_end = self.serialized.len();

                self.process_authority(authority, authority_end)?;
            }

            Ok(())
        } else {
            Err(UrlParseError::new("invalid URL"))
        }
    }

    /// Process the authority part.
    fn process_authority(&mut self, start: usize, end: usize) -> Result<()> {
        if let Some(delim) = self.serialized[start..end].rfind('@') {
            self.process_user_info(start, start + delim);

            self.netloc = start + delim + 1;
        } else {
            self.netloc = start;
        }

        let netloc = &self.serialized[self.netloc..end];

        if !netloc.ends_with(']') {
            if let Some(delim) = netloc.rfind(':') {
                let ppos = delim + 1;
                let port = u16::from_str(&netloc[ppos..])
                    .map_err(|_| UrlParseError::new("invalid port"))?;

                self.portpos = Some(self.netloc + ppos);
                self.port = Some(port);
            }
        }

        Ok(())
    }

    /// Process user info.
    fn process_user_info(&mut self, start: usize, end: usize) {
        let uinfo = &self.serialized[start..end];

        self.username = Some(start);

        if let Some(delim) = uinfo.find(':') {
            self.password = Some(start + delim + 1);
        }
    }

    /// Process the path part and everything that follows it.
    fn process_path(&mut self, start: usize) {
        let path = &self.serialized[start..];

        self.path = Some(start);

        if let Some(delim) = path.rfind('#') {
            self.fragment = Some(start + delim + 1);
        }

        let end = self.fragment.map_or(self.serialized.len(), |f| f - 1);

        let path = &self.serialized[start..end];

        if let Some(delim) = path.rfind('?') {
            self.query = Some(start + delim + 1);
        }
    }

    /// Get URL scheme.
    pub fn scheme(&self) -> &str {
        &self.serialized[..self.hier - 1]
    }

    /// Get username.
    pub fn username(&self) -> Option<&str> {
        if let Some(uname_pos) = self.username {
            if let Some(pwd_pos) = self.password {
                Some(&self.serialized[uname_pos..pwd_pos - 1])
            } else {
                Some(&self.serialized[uname_pos..self.netloc - 1])
            }
        } else {
            None
        }
    }

    /// Get password.
    pub fn password(&self) -> Option<&str> {
        self.password
            .map(|pwd_pos| &self.serialized[pwd_pos..self.netloc - 1])
    }

    /// Get host.
    pub fn host(&self) -> &str {
        if let Some(portpos) = self.portpos {
            &self.serialized[self.netloc..portpos - 1]
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
                &self.serialized[path..query - 1]
            } else if let Some(fragment) = self.fragment {
                &self.serialized[path..fragment - 1]
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
                Some(&self.serialized[query..fragment - 1])
            } else {
                Some(&self.serialized[query..])
            }
        } else {
            None
        }
    }

    /// Get fragment.
    pub fn fragment(&self) -> Option<&str> {
        self.fragment.map(|fragment| &self.serialized[fragment..])
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

    fn from_str(s: &str) -> Result<Self> {
        let mut url = Self {
            serialized: s.to_string(),
            hier: 0,
            netloc: 0,
            username: None,
            password: None,
            portpos: None,
            port: None,
            path: None,
            query: None,
            fragment: None,
        };

        url.init()?;

        Ok(url)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_plain_hostname() {
        let url = Url::from_str("foo");

        assert!(url.is_err());
    }

    #[test]
    fn test_no_authority() {
        let url = Url::from_str("foo:bar");

        assert!(url.is_err());
    }

    #[test]
    fn test_invalid_port() {
        let url = Url::from_str("http://foo:100000");

        assert!(url.is_err());
    }

    #[test]
    fn test_minimal_url() {
        let url = Url::from_str("http://foo").unwrap();

        assert_eq!(url.scheme(), "http");
        assert_eq!(url.username(), None);
        assert_eq!(url.password(), None);
        assert_eq!(url.host(), "foo");
        assert_eq!(url.port(), None);
        assert_eq!(url.path(), "/");
        assert_eq!(url.query(), None);
        assert_eq!(url.fragment(), None);
    }

    #[test]
    fn test_empty_port() {
        let url = Url::from_str("http://foo:12").unwrap();

        assert_eq!(url.scheme(), "http");
        assert_eq!(url.username(), None);
        assert_eq!(url.password(), None);
        assert_eq!(url.host(), "foo");
        assert_eq!(url.port(), Some(12));
        assert_eq!(url.path(), "/");
        assert_eq!(url.query(), None);
        assert_eq!(url.fragment(), None);
    }

    #[test]
    fn test_empty_username() {
        let url = Url::from_str("http://@foo/some/path").unwrap();

        assert_eq!(url.scheme(), "http");
        assert_eq!(url.username(), Some(""));
        assert_eq!(url.password(), None);
        assert_eq!(url.host(), "foo");
        assert_eq!(url.port(), None);
        assert_eq!(url.path(), "/some/path");
        assert_eq!(url.query(), None);
        assert_eq!(url.fragment(), None);
    }

    #[test]
    fn test_no_password() {
        let url = Url::from_str("http://user@foo/").unwrap();

        assert_eq!(url.scheme(), "http");
        assert_eq!(url.username(), Some("user"));
        assert_eq!(url.password(), None);
        assert_eq!(url.host(), "foo");
        assert_eq!(url.port(), None);
        assert_eq!(url.path(), "/");
        assert_eq!(url.query(), None);
        assert_eq!(url.fragment(), None);
    }

    #[test]
    fn test_empty_password() {
        let url = Url::from_str("http://user:@foo/").unwrap();

        assert_eq!(url.scheme(), "http");
        assert_eq!(url.username(), Some("user"));
        assert_eq!(url.password(), Some(""));
        assert_eq!(url.host(), "foo");
        assert_eq!(url.port(), None);
        assert_eq!(url.path(), "/");
        assert_eq!(url.query(), None);
        assert_eq!(url.fragment(), None);
    }

    #[test]
    fn test_password() {
        let url = Url::from_str("http://user:pass@foo/").unwrap();

        assert_eq!(url.scheme(), "http");
        assert_eq!(url.username(), Some("user"));
        assert_eq!(url.password(), Some("pass"));
        assert_eq!(url.host(), "foo");
        assert_eq!(url.port(), None);
        assert_eq!(url.path(), "/");
        assert_eq!(url.query(), None);
        assert_eq!(url.fragment(), None);
    }

    #[test]
    fn test_fragment_and_query() {
        let url = Url::from_str("http://foo/some/path?and=query&a=b#and-fragment").unwrap();

        assert_eq!(url.scheme(), "http");
        assert_eq!(url.username(), None);
        assert_eq!(url.password(), None);
        assert_eq!(url.host(), "foo");
        assert_eq!(url.port(), None);
        assert_eq!(url.path(), "/some/path");
        assert_eq!(url.query(), Some("and=query&a=b"));
        assert_eq!(url.fragment(), Some("and-fragment"));
    }

    #[test]
    fn test_query_alone() {
        let url = Url::from_str("http://foo/some/path?and=query&a=b").unwrap();

        assert_eq!(url.scheme(), "http");
        assert_eq!(url.username(), None);
        assert_eq!(url.password(), None);
        assert_eq!(url.host(), "foo");
        assert_eq!(url.port(), None);
        assert_eq!(url.path(), "/some/path");
        assert_eq!(url.query(), Some("and=query&a=b"));
        assert_eq!(url.fragment(), None);
    }

    #[test]
    fn test_fragment_alone() {
        let url = Url::from_str("http://foo/some/path#and-fragment").unwrap();

        assert_eq!(url.scheme(), "http");
        assert_eq!(url.username(), None);
        assert_eq!(url.password(), None);
        assert_eq!(url.host(), "foo");
        assert_eq!(url.port(), None);
        assert_eq!(url.path(), "/some/path");
        assert_eq!(url.query(), None);
        assert_eq!(url.fragment(), Some("and-fragment"));
    }

    #[test]
    fn test_full_featured_url() {
        let url =
            Url::from_str("http://user:pass@foo:123/some/path?and=query&a=b#and-fragment").unwrap();

        assert_eq!(url.scheme(), "http");
        assert_eq!(url.username(), Some("user"));
        assert_eq!(url.password(), Some("pass"));
        assert_eq!(url.host(), "foo");
        assert_eq!(url.port(), Some(123));
        assert_eq!(url.path(), "/some/path");
        assert_eq!(url.query(), Some("and=query&a=b"));
        assert_eq!(url.fragment(), Some("and-fragment"));
    }
}
