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
use std::str::Chars;

/// String reader error.
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
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        f.write_str(&self.msg)
    }
}

impl<'a> From<&'a str> for ParseError {
    fn from(msg: &'a str) -> Self {
        Self {
            msg: msg.to_string(),
        }
    }
}

/// Result.
pub type Result<T> = result::Result<T, ParseError>;

/// Custom string reader.
pub struct Reader<'a> {
    input: Chars<'a>,
    current: Option<char>,
}

impl<'a> Reader<'a> {
    /// Create a new reader for a given input.
    pub fn new<T>(input: &'a T) -> Reader<'a>
    where
        T: AsRef<str> + ?Sized,
    {
        let input = input.as_ref().chars();

        // We do not want to advance the input just yet. If did that the string
        // matching methods would not work.
        let current = input.clone().next();

        Reader { input, current }
    }

    /// Get current character (if any) without advancing the input.
    pub fn current_char(&self) -> Option<char> {
        self.current
    }

    /// Get the next character or return an error if the input is empty.
    pub fn read_char(&mut self) -> Result<char> {
        let res = self
            .input
            .next()
            .ok_or_else(|| ParseError::from("input is empty"))?;

        // Peek for the next character without advancing the input.
        self.current = self.input.clone().next();

        Ok(res)
    }

    /// Match a given character to the input.
    pub fn match_char(&mut self, expected: char) -> Result<()> {
        let c = self
            .current_char()
            .ok_or_else(|| ParseError::from("input is empty"))?;

        if c != expected {
            return Err(ParseError::from("unexpected character"));
        }

        self.skip_char();

        Ok(())
    }

    /// Skip one character.
    pub fn skip_char(&mut self) {
        // Remove the current character.
        self.input.next();

        // Peek for the next character without advancing the input.
        self.current = self.input.clone().next();
    }

    /// Skip whitespace characters.
    pub fn skip_whitespace(&mut self) {
        while let Some(c) = self.current_char() {
            if c.is_whitespace() {
                self.skip_char();
            } else {
                break;
            }
        }
    }

    /// Match a given string to the input.
    pub fn match_str(&mut self, val: &str) -> Result<()> {
        let input = self.input.as_str();

        if input.starts_with(val) {
            let (_, rest) = input.split_at(val.len());

            self.input = rest.chars();

            // Peek for the next character without advancing the input.
            self.current = self.input.clone().next();

            Ok(())
        } else {
            Err(ParseError::from("string does not match"))
        }
    }

    /// Read a decimal integer as u32. The method skips all the initial
    /// whitespace (if any).
    pub fn read_decimal_u32(&mut self) -> Result<u32> {
        let mut res = 0_u32;
        let mut cnt = 0_u32;

        self.skip_whitespace();

        while let Some(c) = self.current_char() {
            if let Some(digit) = c.to_digit(10) {
                res = res * 10 + digit;
            } else {
                break;
            }

            cnt += 1;

            self.skip_char();
        }

        if cnt == 0 {
            Err(ParseError::from("no integer found"))
        } else {
            Ok(res)
        }
    }

    /// Read until a given condition is true or until the end of the input.
    pub fn read_until<F>(&mut self, cnd: F) -> &'a str
    where
        F: FnMut(char) -> bool,
    {
        let rest = self.input.as_str();

        let index = rest.find(cnd).unwrap_or_else(|| rest.len());

        let (word, rest) = rest.split_at(index);

        self.input = rest.chars();

        // Peek for the next character without advancing the input.
        self.current = self.input.clone().next();

        word
    }

    /// Read one word from the input. A word ends with the first whitespace or
    /// with the end of the input. The method skips all the initial whitespace
    /// (if any).
    pub fn read_word(&mut self) -> &'a str {
        self.skip_whitespace();
        self.read_until(char::is_whitespace)
    }

    /// Check if the reader is empty.
    pub fn is_empty(&self) -> bool {
        self.current_char().is_none()
    }

    /// Get the rest of the input.
    pub fn as_str(&self) -> &'a str {
        self.input.as_str()
    }
}

#[cfg(test)]
#[test]
fn test_reader() {
    let input = "Hello, World!!!   1234\n\tfoo-bar";

    let mut reader = Reader::new(input);

    assert!(!reader.is_empty());
    assert_eq!(reader.current_char(), Some('H'));
    assert_eq!(reader.as_str(), input);

    let word = reader.read_word();

    assert_eq!(word, "Hello,");
    assert_eq!(reader.as_str(), " World!!!   1234\n\tfoo-bar");

    reader.skip_whitespace();

    assert_eq!(reader.as_str(), "World!!!   1234\n\tfoo-bar");

    let c = reader.read_char();

    assert_eq!(c.ok(), Some('W'));

    let res = reader.match_char('o');

    assert!(res.is_ok());

    let res = reader.match_char('R');

    assert!(res.is_err());

    let res = reader.match_str("RLD!!!");

    assert!(res.is_err());

    let res = reader.match_str("rld!!!");

    assert!(res.is_ok());
    assert_eq!(reader.as_str(), "   1234\n\tfoo-bar");

    let n = reader.read_decimal_u32();

    assert_eq!(n.ok(), Some(1234));
    assert_eq!(reader.as_str(), "\n\tfoo-bar");

    let n = reader.read_decimal_u32();

    assert!(n.is_err());
    assert_eq!(reader.as_str(), "foo-bar");

    let word = reader.read_word();

    assert_eq!(word, "foo-bar");
    assert_eq!(reader.as_str(), "");
    assert!(reader.is_empty());

    let word = reader.read_word();

    assert_eq!(word, "");

    let c = reader.read_char();

    assert!(c.is_err());
    assert!(reader.is_empty());
    assert_eq!(reader.as_str(), "");
}
