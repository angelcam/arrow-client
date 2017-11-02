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

//! RTSP client definitions (only OPTIONS and DESCRIBE methods are currently
//! implemented.

pub mod sdp;

use std::io;
use std::fmt;
use std::result;
use std::str;

use std::error::Error;
use std::str::FromStr;
use std::time::Duration;
use std::net::TcpStream;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::fmt::{Display, Formatter, Debug};

use net::utils;

use utils::RuntimeError;

use utils::string::reader::Reader;

pub use net::http::{LineReader, ParseError, ParsingResult};

/// Error returned by RTSP client.
#[derive(Debug, Clone)]
pub struct RtspError {
    msg: String,
}

impl Error for RtspError {
    fn description(&self) -> &str {
        &self.msg
    }
}

impl Display for RtspError {
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        f.write_str(&self.msg)
    }
}

impl From<String> for RtspError {
    fn from(msg: String) -> RtspError {
        RtspError { msg: msg }
    }
}

impl<'a> From<&'a str> for RtspError {
    fn from(msg: &'a str) -> RtspError {
        RtspError::from(msg.to_string())
    }
}

impl From<io::Error> for RtspError {
    fn from(err: io::Error) -> RtspError {
        RtspError::from(format!("IO error: {}", err))
    }
}

impl From<ParseError> for RtspError {
    fn from(err: ParseError) -> RtspError {
        RtspError::from(format!("parse error: {}", err))
    }
}

impl From<RuntimeError> for RtspError {
    fn from(err: RuntimeError) -> RtspError {
        RtspError::from(format!("{}", err))
    }
}

/// RTSP client result type.
pub type Result<T> = result::Result<T, RtspError>;

/// Header field type alias.
type Header = (String, String);

/// RTSP method.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Method {
    OPTIONS,
    DESCRIBE,
}

impl Method {
    /// Get method name.
    fn name(self) -> &'static str {
        match self {
            Method::OPTIONS  => "OPTIONS",
            Method::DESCRIBE => "DESCRIBE",
        }
    }
}

/// RTSP request.
struct Request {
    method:   Method,
    endpoint: String,
    headers:  Vec<Header>,
}

impl Request {
    /// Create a new request.
    fn new(method: Method, endpoint: &str) -> Request {
        Request {
            method:   method,
            endpoint: endpoint.to_string(),
            headers:  Vec::new()
        }
    }

    /// Add a new header field into the request.
    fn add_header<N, V>(mut self, name: N, value: V) -> Request
        where N: ToString, V: ToString {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
}

impl Display for Request {
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        f.write_str(
            &format!("{} {} RTSP/1.0\r\n", self.method.name(), &self.endpoint)
        )?;

        for &(ref name, ref val) in &self.headers {
            f.write_str(&format!("{}: {}\r\n", name, val))?;
        }

        f.write_str("\r\n")
    }
}

/// RTSP response.
#[derive(Debug, Clone)]
pub struct Response {
    pub header: ResponseHeader,
    pub body:   Vec<u8>,
}

impl Response {
    /// Create a new RTSP response.
    fn new(header: ResponseHeader, body: Vec<u8>) -> Response {
        Response {
            header: header,
            body:   body,
        }
    }
}

impl Display for Response {
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        let body = String::from_utf8_lossy(&self.body);
        Display::fmt(&self.header, f)?;
        f.write_str(&body)
    }
}

/// RTSP client response header.
#[derive(Debug, Clone)]
pub struct ResponseHeader {
    pub code:   i32,
    pub line:   String,
    headers:    Vec<Header>,
    header_map: HashMap<String, usize>,
}

impl ResponseHeader {
    /// Create a new RTSP response header.
    fn new(
        code: i32,
        line: String,
        headers: Vec<Header>) -> ResponseHeader {
        let mut res = ResponseHeader {
            code:       code,
            line:       line,
            headers:    headers,
            header_map: HashMap::new()
        };

        for i in 0..res.headers.len() {
            let &(ref name, _) = res.headers.get(i).unwrap();
            res.header_map.insert(name.to_lowercase(), i);
        }

        res
    }

    /// Get response header value.
    pub fn get<T: FromStr>(&self, name: &str) -> Option<T>
        where T::Err: Debug {
        let key = name.to_lowercase();
        if let Some(i) = self.header_map.get(&key) {
            let &(_, ref val) = self.headers.get(*i).unwrap();
            let res = T::from_str(val);
            Some(res.unwrap())
        } else {
            None
        }
    }

    /// Get response header value string without copying it.
    pub fn get_str<'a>(&'a self, name: &str) -> Option<&'a str> {
        let key = name.to_lowercase();
        if let Some(i) = self.header_map.get(&key) {
            let &(_, ref val) = self.headers.get(*i).unwrap();
            Some(val)
        } else {
            None
        }
    }
}

impl Display for ResponseHeader {
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        f.write_str(
            &format!("RTSP/1.0 {} {}\r\n", self.code, &self.line)
        )?;

        for &(ref name, ref value) in &self.headers {
            f.write_str(&format!("{}: {}\r\n", name, value))?;
        }

        f.write_str("\r\n")
    }
}

/// RTSP response header parser.
struct ResponseHeaderParser {
    status_code: i32,
    status_line: String,
    headers:     Vec<Header>,
    max_lines:   usize,
    lines:       usize,
    complete:    bool,
}

impl ResponseHeaderParser {
    /// Create a new response header parser with a given header line limit.
    fn new(max_lines: usize) -> ResponseHeaderParser {
        ResponseHeaderParser {
            status_code: 0,
            status_line: String::new(),
            headers:     Vec::new(),
            max_lines:   max_lines,
            lines:       0,
            complete:    false
        }
    }

    /// Check if the current header is complete.
    fn is_complete(&self) -> bool {
        self.complete
    }

    /// Parse a given header line.
    fn add(&mut self, line: &str) -> ParsingResult<()> {
        if self.lines >= self.max_lines {
            return Err(ParseError::from("maximum number of RTSP header lines exceeded"));
        } else if self.lines > 0 {
            self.parse_header_line(line)?;
        } else {
            self.parse_status_line(line)?;
        }

        self.lines += 1;

        Ok(())
    }

    /// Parse RTSP status line.
    fn parse_status_line(&mut self, line: &str) -> ParsingResult<()> {
        let mut reader = Reader::new(line);

        reader.match_str("RTSP/1.0")
            .map_err(|_| ParseError::from("invalid RTSP status line"))?;

        reader.skip_whitespace();
        let sc = reader.read_decimal_u32()
            .map_err(|_| ParseError::from("invalid RTSP status line"))?;
        reader.skip_whitespace();
        let sl = reader.as_str()
            .to_string();

        self.status_code = sc as i32;
        self.status_line = sl;

        Ok(())
    }

    /// Parse RTSP header line.
    fn parse_header_line(&mut self, line: &str) -> ParsingResult<()> {
        let mut chars = line.chars();

        if let Some(c) = chars.next() {
            if c.is_whitespace() {
                if let Some((name, val)) = self.headers.pop() {
                    self.headers.push((name, val + line.trim_left()));
                } else {
                    return Err(ParseError::from("first RTSP header cannot be continuation"));
                }
            } else if let Some(delim) = line.find(':') {
                let (name, value) = line.split_at(delim);

                let value = &value[1..];

                let name = name.trim();
                let value = value.trim();

                self.headers.push((name.to_string(), value.to_string()));
            } else {
                return Err(ParseError::from("invalid RTSP header line"));
            }
        } else {
            self.complete = true;
        }

        Ok(())
    }

    /// Clear the parser.
    fn clear(&mut self) {
        self.status_code = 0;
        self.status_line = String::new();
        self.lines       = 0;
        self.complete    = false;

        self.headers.clear();
    }

    /// Get current response header.
    fn header(&self) -> ParsingResult<ResponseHeader> {
        if self.complete {
            let res = ResponseHeader::new(
                self.status_code,
                self.status_line.clone(),
                self.headers.clone());

            Ok(res)
        } else {
            Err(ParseError::from("incomplete RTSP header"))
        }
    }
}

/// RTSP response parser.
struct ResponseParser {
    line_reader:    LineReader,
    header_parser:  ResponseHeaderParser,
    header:         Option<ResponseHeader>,
    body:           Vec<u8>,
    expected:       usize,
}

impl ResponseParser {
    /// Create a new response parser.
    fn new(max_line_length: usize, max_lines: usize) -> ResponseParser {
        ResponseParser {
            line_reader:   LineReader::new(max_line_length, b"\r\n"),
            header_parser: ResponseHeaderParser::new(max_lines),
            header:        None,
            body:          Vec::new(),
            expected:      0
        }
    }

    /// Check if the RTSP response is complete.
    fn is_complete(&self) -> bool {
        self.header.is_some() && self.expected == 0
    }

    /// Get the last response.
    fn response(&self) -> ParsingResult<Response> {
        match self.header {
            Some(ref header) if self.expected == 0 => {
                let header = header.clone();
                let body   = self.body.clone();
                Ok(Response::new(header, body))
            },
            _ => Err(ParseError::from("incomplete RTSP response"))
        }
    }

    /// Clear the current message.
    fn clear(&mut self) {
        self.line_reader.clear();
        self.header_parser.clear();
        self.body.clear();

        self.header   = None;
        self.expected = 0;
    }

    /// Process a given chunk of data and return the number of bytes used.
    fn add(&mut self, chunk: &[u8]) -> ParsingResult<usize> {
        let mut pos = 0;

        while pos < chunk.len() && !self.is_complete() {
            if self.header.is_none() {
                pos += self.process_header_data(&chunk[pos..])?;
            } else {
                pos += self.process_body_data(&chunk[pos..])
            }
        }

        Ok(pos)
    }

    /// Process given header data.
    fn process_header_data(&mut self, data: &[u8]) -> ParsingResult<usize> {
        let mut pos = 0;

        while pos < data.len() && self.header.is_none() {
            pos += self.line_reader.add(&data[pos..])?;
            if self.line_reader.is_complete() {
                {
                    let line = self.line_reader.line();
                    let line = str::from_utf8(line)?;

                    self.header_parser.add(line)?;
                }

                if self.header_parser.is_complete() {
                    let header = self.header_parser.header()?;

                    self.expected = header.get("content-length")
                        .unwrap_or(0);

                    self.header = Some(header);
                }

                self.line_reader.clear();
            }
        }

        Ok(pos)
    }

    /// Process given body data.
    fn process_body_data(&mut self, data: &[u8]) -> usize {
        let mut pos = 0;

        while pos < data.len() && !self.is_complete() {
            let buffer = &data[pos..];
            let len = if self.expected > buffer.len() {
                buffer.len()
            } else {
                self.expected
            };

            self.body.extend_from_slice(&buffer[..len]);

            self.expected -= len;
            pos           += len;
        }

        pos
    }
}

/// RTSP client.
pub struct Client {
    parser: ResponseParser,
    stream: TcpStream,
    host:   String,
    port:   u16,
    buffer: Vec<u8>,
    offset: usize,
}

impl Client {
    /// Create a new RTSP client for a given remote service.
    pub fn new(host: &str, port: u16) -> Result<Client> {
        let address = utils::get_socket_address((host, port))?;
        let stream  = TcpStream::connect(&address)?;

        let client = Client {
            parser: ResponseParser::new(4096, 256),
            stream: stream,
            host:   host.to_string(),
            port:   port,
            buffer: Vec::new(),
            offset: 0
        };

        Ok(client)
    }

    /// Set timeout for read and write operations.
    pub fn set_timeout(&mut self, ms: Option<u64>) -> Result<()> {
        let duration = ms.map(|ms| Duration::from_millis(ms));
        self.stream.set_read_timeout(duration)?;
        self.stream.set_write_timeout(duration)?;
        Ok(())
    }

    /// Send OPTIONS command.
    pub fn options(&mut self) -> Result<Response> {
        let request = self.create_request(Method::OPTIONS, "/", 1);

        self.perform_request(&request)
    }

    /// Send DESCRIBE command.
    pub fn describe(&mut self, path: &str) -> Result<Response> {
        let request = self.create_request(Method::DESCRIBE, path, 1)
            .add_header("Accept", "application/sdp");

        self.perform_request(&request)
    }

    /// Create an RTSP request for a given method, path and sequence number.
    fn create_request(
        &self,
        method: Method,
        path: &str,
        cseq: usize) -> Request {
        let version  = env!("CARGO_PKG_VERSION");
        let uagent   = format!("ArrowClient/{}", version);
        let endpoint = format!("rtsp://{}:{}{}", self.host, self.port, path);

        Request::new(method, &endpoint)
            .add_header("CSeq", cseq)
            .add_header("User-Agent", &uagent)
    }

    /// Send a given request and wait for response.
    fn perform_request(&mut self, request: &Request) -> Result<Response> {
        let request = format!("{}", request)
            .into_bytes();

        self.stream.write_all(&request)?;

        // process buffered data
        while self.offset < self.buffer.len() && !self.parser.is_complete() {
            let data = &self.buffer[self.offset..];
            self.offset += self.parser.add(data)?;
        }

        // reset the buffer if it's empty
        if self.offset >= self.buffer.len() {
            self.buffer.clear();
            self.offset = 0;
        }

        let mut buffer = [0u8; 4096];

        while !self.parser.is_complete() {
            let length = self.stream.read(&mut buffer)?;

            if length == 0 {
                break;
            }

            let mut offset = 0;

            while offset < length && !self.parser.is_complete() {
                offset += self.parser.add(&buffer[offset..length])?;
            }

            // put all possible leftovers into the internal buffer
            if offset < length {
                self.buffer.extend_from_slice(&buffer[offset..length]);
            }
        }

        let response = self.parser.response()?;

        self.parser.clear();

        Ok(response)
    }
}

#[cfg(test)]
#[test]
fn test_rtsp_request() {
    let request = Request::new(Method::DESCRIBE, "rtsp://127.0.0.1:554/foo")
        .add_header("CSeq", 1)
        .add_header("Connection", "close");

    let expected = "DESCRIBE rtsp://127.0.0.1:554/foo RTSP/1.0\r\n".to_string()
        + "CSeq: 1\r\n"
        + "Connection: close\r\n"
        + "\r\n";

    let msg = format!("{}", request);

    assert_eq!(expected, msg);
}

#[cfg(test)]
#[test]
fn test_rtsp_response() {
    let mut header_fields = Vec::new();
    header_fields.push(("CSeq".to_string(), "1".to_string()));
    header_fields.push(("Content-Length".to_string(), "5".to_string()));

    let header = ResponseHeader::new(200, "OK".to_string(), header_fields);
    let body   = "hello".as_bytes()
        .to_vec();

    let response = Response::new(header, body);

    let expected = "RTSP/1.0 200 OK\r\n".to_string()
        + "CSeq: 1\r\n"
        + "Content-Length: 5\r\n"
        + "\r\n"
        + "hello";

    let msg = format!("{}", response);

    assert_eq!(expected, msg);

    let mut parser = ResponseParser::new(4096, 256);

    parser.add(expected.as_bytes())
        .unwrap();

    let response = parser.response()
        .unwrap();

    assert_eq!(response.header.code, 200);
    assert_eq!(response.header.line, "OK");
    assert_eq!(response.header.get("cseq"), Some(1));
    assert_eq!(response.body, b"hello")
}
