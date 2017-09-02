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

//! Simple HTTP client definitions. The client implements only the HEAD and GET
//! methods as it is used only for fingerprinting open TCP ports.

use std::io;
use std::str;
use std::num;
use std::fmt;
use std::result;

use std::error::Error;
use std::str::FromStr;
use std::time::Duration;
use std::net::TcpStream;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::fmt::{Display, Debug, Formatter};

use net::utils;

use utils::RuntimeError;

use regex::Regex;

/// Message parse error.
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

impl From<num::ParseIntError> for ParseError {
    fn from(_: num::ParseIntError) -> ParseError {
        ParseError::from("integer parsing error")
    }
}

impl From<str::Utf8Error> for ParseError {
    fn from(_: str::Utf8Error) -> ParseError {
        ParseError::from("UTF-8 parsing error")
    }
}

/// Message parsing result type.
pub type ParsingResult<T> = result::Result<T, ParseError>;

/// Header field type alias.
pub type Header = (String, String);

/// HTTP method.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Method {
    HEAD,
    GET,
}

impl Method {
    /// Get method name.
    fn name(self) -> &'static str {
        match self {
            Method::HEAD => "HEAD",
            Method::GET  => "GET",
        }
    }
}

/// HTTP request.
#[derive(Debug, Clone)]
struct Request {
    method:  Method,
    path:    String,
    headers: Vec<Header>,
}

impl Request {
    /// Create a new request.
    fn new(method: Method, path: &str) -> Request {
        Request {
            method:  method,
            path:    path.to_string(),
            headers: Vec::new()
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
        try!(f.write_str(&format!("{} {} HTTP/1.0\r\n",
            self.method.name(), &self.path)));
        for &(ref name, ref val) in &self.headers {
            try!(f.write_str(&format!("{}: {}\r\n", name, val)));
        }
        f.write_str("\r\n")
    }
}

/// HTTP response.
#[derive(Debug, Clone)]
pub struct Response {
    pub header: ResponseHeader,
    pub body:   Vec<u8>,
}

impl Response {
    /// Create a new HTTP response.
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
        try!(Display::fmt(&self.header, f));
        f.write_str(&body)
    }
}

/// HTTP client response header.
#[derive(Debug, Clone)]
pub struct ResponseHeader {
    version:    String,
    pub code:   i32,
    pub line:   String,
    headers:    Vec<Header>,
    header_map: HashMap<String, usize>,
}

impl ResponseHeader {
    /// Create a new HTTP response header.
    fn new() -> ResponseHeader {
        ResponseHeader {
            version:    String::new(),
            code:       0,
            line:       String::new(),
            headers:    Vec::new(),
            header_map: HashMap::new()
        }
    }

    /// Get response header value.
    pub fn get<T: FromStr>(&self, name: &str) -> Option<T>
        where T::Err: Debug {
        let key = name.to_lowercase();
        if let Some(i) = self.header_map.get(&key) {
            let &(_, ref val) = self.headers.get(*i)
                .unwrap();

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
            let &(_, ref val) = self.headers.get(*i)
                .unwrap();

            Some(val)
        } else {
            None
        }
    }
}

impl Display for ResponseHeader {
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        try!(f.write_str(&format!("HTTP/{} {} {}\r\n",
            &self.version, self.code, &self.line)));
        for &(ref name, ref value) in &self.headers {
            try!(f.write_str(&format!("{}: {}\r\n", name, value)));
        }

        f.write_str("\r\n")
    }
}

/// HTTP response header parser.
struct ResponseHeaderParser {
    status_re:   Regex,
    header_re:   Regex,
    cont_re:     Regex,
    header:      ResponseHeader,
    max_lines:   usize,
    lines:       usize,
    complete:    bool,
}

impl ResponseHeaderParser {
    /// Create a new response header parser with a given header line limit.
    fn new(max_lines: usize) -> ResponseHeaderParser {
        ResponseHeaderParser {
            status_re:   Regex::new(r"^HTTP/(\d\.\d) (\d+) (.*)$").unwrap(),
            header_re:   Regex::new(r"^([^ :]+):\s*(.*)$").unwrap(),
            cont_re:     Regex::new(r"^\s+(.*)$").unwrap(),
            header:      ResponseHeader::new(),
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
            return Err(ParseError::from("maximum number of HTTP header lines exceeded"));
        } else if self.lines > 0 {
            try!(self.parse_header_line(line));
        } else {
            try!(self.parse_status_line(line));
        }

        self.lines += 1;

        Ok(())
    }

    /// Parse HTTP status line.
    fn parse_status_line(&mut self, line: &str) -> ParsingResult<()> {
        if let Some(caps) = self.status_re.captures(line) {
            let version     = caps.get(1).unwrap().as_str();
            let status_code = caps.get(2).unwrap().as_str();
            let status_line = caps.get(3).unwrap().as_str();

            self.header.code    = try!(i32::from_str(status_code));
            self.header.line    = status_line.to_string();
            self.header.version = version.to_string();

            Ok(())
        } else {
            Err(ParseError::from("invalid HTTP status line"))
        }
    }

    /// Parse HTTP header line.
    fn parse_header_line(&mut self, line: &str) -> ParsingResult<()> {
        if line.is_empty() {
            for i in 0..self.header.headers.len() {
                let &(ref name, _) = self.header.headers.get(i)
                    .unwrap();

                self.header.header_map.insert(name.to_lowercase(), i);
            }
            self.complete = true;
        } else if let Some(caps) = self.header_re.captures(line) {
            let name  = caps.get(1).unwrap().as_str();
            let value = caps.get(2).unwrap().as_str();
            self.header.headers.push((name.to_string(), value.to_string()));
        } else if let Some(caps) = self.cont_re.captures(line) {
            let cont = caps.get(1).unwrap().as_str();

            if let Some((name, val)) = self.header.headers.pop() {
                self.header.headers.push((name, val + cont));
            } else {
                return Err(ParseError::from("first HTTP header cannot be continuation"));
            }
        } else {
            return Err(ParseError::from("invalid HTTP header line"));
        }

        Ok(())
    }

    /// Get current response header.
    fn header(&self) -> ParsingResult<&ResponseHeader> {
        if self.complete {
            Ok(&self.header)
        } else {
            Err(ParseError::from("incomplete HTTP header"))
        }
    }
}

/// Line reader.
pub struct LineReader {
    buffer:    Vec<u8>,
    separator: Vec<u8>,
    max_len:   usize,
    complete:  bool,
}

impl LineReader {
    /// Create a new line reader with a given maximum line length and line
    /// separator.
    pub fn new(max_length: usize, separator: &[u8]) -> LineReader {
        LineReader {
            buffer:    Vec::new(),
            separator: separator.to_vec(),
            max_len:   max_length,
            complete:  false
        }
    }

    /// Check if the current line is complete.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Get current line.
    pub fn line(&self) -> &[u8] {
        &self.buffer
    }

    /// Append given data and return the number of bytes used.
    pub fn add(&mut self, data: &[u8]) -> ParsingResult<usize> {
        if self.complete {
            return Ok(0);
        }

        let buf_len   = self.buffer.len();
        let sep_len   = self.separator.len();
        let available = self.max_len - buf_len;

        let consume = if available > data.len() {
            data.len()
        } else {
            available
        };

        let start = if sep_len < buf_len {
            buf_len - sep_len
        } else {
            0
        };

        self.buffer.extend_from_slice(&data[..consume]);

        if let Some(pos) = self.find_separator(start) {
            self.buffer.resize(pos, 0);
            self.complete = true;
            Ok(pos + sep_len - buf_len)
        } else if consume < data.len() {
            Err(ParseError::from("line length exceeded"))
        } else {
            Ok(consume)
        }
    }

    /// Clear the current line.
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.complete = false;
    }

    /// Try to find the separator in the internal buffer starting at a given
    /// offset.
    fn find_separator(&self, offset: usize) -> Option<usize> {
        for i in offset..self.buffer.len() {
            let haystack = &self.buffer[i..];
            if haystack.starts_with(&self.separator) {
                return Some(i);
            }
        }

        None
    }
}

/// HTTP/1.0 response parser.
struct ResponseParser<'a, H: 'static + ResponseHandler> {
    line_reader:      LineReader,
    header_parser:    ResponseHeaderParser,
    response_handler: &'a mut H,
}

impl<'a, H> ResponseParser<'a, H> where H: 'static + ResponseHandler {
    /// Create a new response parser.
    fn new(
        rhandler: &'a mut H,
        max_line_length: usize,
        max_lines: usize) -> ResponseParser<'a, H> {
        ResponseParser {
            line_reader:      LineReader::new(max_line_length, b"\r\n"),
            header_parser:    ResponseHeaderParser::new(max_lines),
            response_handler: rhandler
        }
    }

    /// Process a given chunk of data. This method returns true to keep
    /// processing, false otherwise.
    fn add(&mut self, chunk: &[u8]) -> ParsingResult<bool> {
        let mut pos = 0;

        while pos < chunk.len() {
            if self.header_parser.is_complete() {
                if self.response_handler.body(&chunk[pos..]) {
                    pos = chunk.len();
                } else {
                    return Ok(false);
                }
            } else {
                pos += try!(self.line_reader.add(&chunk[pos..]));
                if self.line_reader.is_complete() {
                    if try!(self.process_header_line()) {
                        self.line_reader.clear();
                    } else {
                        return Ok(false);
                    }
                }
            }
        }

        Ok(true)
    }

    /// Process the current header line.
    fn process_header_line(&mut self) -> ParsingResult<bool> {
        {
            let line = self.line_reader.line();
            let line = try!(str::from_utf8(line));

            try!(self.header_parser.add(line));
        }

        if self.header_parser.is_complete() {
            self.process_header()
        } else {
            Ok(true)
        }
    }

    /// Process the current header.
    fn process_header(&mut self) -> ParsingResult<bool> {
        let header = try!(self.header_parser.header());

        Ok(self.response_handler.header(header))
    }
}

/// Response handler trait.
trait ResponseHandler {
    /// Process a given response header and return true in case you wish to
    /// continue processing the rest of the request.
    fn header(&mut self, header: &ResponseHeader) -> bool;

    /// Process a given body chunk and return true in case you wish to continue
    /// processing the rest of the request.
    fn body(&mut self, data: &[u8]) -> bool;

    /// Handle response end.
    fn end(&mut self);
}

/// Simple implementation of the ResponseHandler trait storing the whole
/// response in memory.
struct ResponseBuilder {
    header: Option<ResponseHeader>,
    body:   Vec<u8>,
}

impl ResponseBuilder {
    /// Create a new ResponseBuilder.
    fn new() -> ResponseBuilder {
        ResponseBuilder {
            header: None,
            body:   Vec::new()
        }
    }

    /// Get the Response object.
    fn response(self) -> ParsingResult<Response> {
        if let Some(header) = self.header {
            Ok(Response::new(header, self.body))
        } else {
            Err(ParseError::from("there is no response yet"))
        }
    }
}

impl ResponseHandler for ResponseBuilder {
    fn header(&mut self, header: &ResponseHeader) -> bool {
        self.header = Some(header.clone());
        true
    }

    fn body(&mut self, data: &[u8]) -> bool {
        self.body.extend_from_slice(data);
        true
    }

    fn end(&mut self) {
        // do nothing here
    }
}

/// Simple implementation of the ResponseHandler trait storing only the
/// response header and refusing to process any other data.
struct ResponseHeaderBuilder {
    header: Option<ResponseHeader>,
}

impl ResponseHeaderBuilder {
    /// Create a new response header builder.
    fn new() -> ResponseHeaderBuilder {
        ResponseHeaderBuilder {
            header: None
        }
    }

    /// Get the ResponseHeader obejct.
    fn header(self) -> ParsingResult<ResponseHeader> {
        if let Some(header) = self.header {
            Ok(header)
        } else {
            Err(ParseError::from("there is no response yet"))
        }
    }
}

impl ResponseHandler for ResponseHeaderBuilder {
    fn header(&mut self, header: &ResponseHeader) -> bool {
        self.header = Some(header.clone());
        false
    }

    fn body(&mut self, _: &[u8]) -> bool {
        false
    }

    fn end(&mut self) {
        // do nothing here
    }
}

/// Error returned by HTTP client.
#[derive(Debug, Clone)]
pub struct HttpError {
    msg: String,
}

impl Error for HttpError {
    fn description(&self) -> &str {
        &self.msg
    }
}

impl Display for HttpError {
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        f.write_str(&self.msg)
    }
}

impl From<String> for HttpError {
    fn from(msg: String) -> HttpError {
        HttpError { msg: msg }
    }
}

impl<'a> From<&'a str> for HttpError {
    fn from(msg: &'a str) -> HttpError {
        HttpError::from(msg.to_string())
    }
}

impl From<io::Error> for HttpError {
    fn from(err: io::Error) -> HttpError {
        HttpError::from(format!("IO error: {}", err))
    }
}

impl From<ParseError> for HttpError {
    fn from(err: ParseError) -> HttpError {
        HttpError::from(format!("parse error: {}", err))
    }
}

impl From<RuntimeError> for HttpError {
    fn from(err: RuntimeError) -> HttpError {
        HttpError::from(format!("{}", err))
    }
}

/// HTTP client result type.
pub type Result<T> = result::Result<T, HttpError>;

/// HTTP/1.0 client.
pub struct Client {
    stream: TcpStream,
    host:   String,
}

impl Client {
    /// Create a new HTTP/1.0 client for a given remote service.
    pub fn new(host: &str, port: u16) -> Result<Client> {
        let address        = try!(utils::get_socket_address((host, port)));
        let stream         = try!(TcpStream::connect(&address));
        let client = Client {
            stream: stream,
            host:   host.to_string()
        };

        Ok(client)
    }

    /// Set timeout for read and write operations.
    pub fn set_timeout(&mut self, ms: Option<u64>) -> Result<()> {
        let duration = ms.map(|ms| Duration::from_millis(ms));
        try!(self.stream.set_read_timeout(duration));
        try!(self.stream.set_write_timeout(duration));
        Ok(())
    }

    /// Send a given HEAD request.
    pub fn head(&mut self, path: &str) -> Result<ResponseHeader> {
        let request = self.create_request(Method::HEAD, path)
            .add_header("Accept", "*/*");

        let mut rbuilder = ResponseHeaderBuilder::new();

        try!(self.perform_request(&request, &mut rbuilder));

        Ok(try!(rbuilder.header()))
    }

    /// Send a given GET request.
    pub fn get(&mut self, path: &str, headers: &[Header]) -> Result<Response> {
        let mut request = self.create_request(Method::GET, path);
        for &(ref name, ref value) in headers {
            request = request.add_header(name, value);
        }
        let mut rbuilder = ResponseBuilder::new();

        try!(self.perform_request(&request, &mut rbuilder));

        Ok(try!(rbuilder.response()))
    }

    /// Send a given GET request, wait for the response header and terminate
    /// the connection.
    pub fn get_header(&mut self, path: &str) -> Result<ResponseHeader> {
        let request = self.create_request(Method::GET, path)
            .add_header("Accept", "*/*");

        let mut rbuilder = ResponseHeaderBuilder::new();

        try!(self.perform_request(&request, &mut rbuilder));

        Ok(try!(rbuilder.header()))
    }

    /// Create a HTTP request for a given method and path.
    fn create_request(&self, method: Method, path: &str) -> Request {
        let version = env!("CARGO_PKG_VERSION");
        let uagent  = format!("ArrowClient/{}", version);

        Request::new(method, path)
            .add_header("Host", &self.host)
            .add_header("User-Agent", &uagent)
    }

    /// Send a given request and wait for response.
    fn perform_request<H>(
        &mut self,
        request: &Request,
        rhandler: &mut H) -> Result<()> where H: 'static + ResponseHandler {
        let request = format!("{}", request)
            .into_bytes();

        try!(self.stream.write_all(&request));

        {
            let mut parser = ResponseParser::new(rhandler, 4096, 256);
            let mut buffer = [0u8; 4096];

            let mut length = try!(self.stream.read(&mut buffer));

            while length > 0 {
                if try!(parser.add(&buffer[..length])) {
                    length = try!(self.stream.read(&mut buffer));
                } else {
                    break;
                }
            }
        }

        rhandler.end();

        Ok(())
    }
}

#[cfg(test)]
#[test]
fn test_http_request() {
    let request = Request::new(Method::GET, "/foo")
        .add_header("Accept", "*/*");

    let expected = "GET /foo HTTP/1.0\r\n".to_string()
        + "Accept: */*\r\n"
        + "\r\n";

    let msg = format!("{}", request);

    assert_eq!(expected, msg);
}

#[cfg(test)]
#[test]
fn test_http_response() {
    let mut header_fields = Vec::new();
    let mut header_map    = HashMap::new();

    header_fields.push(("Server".to_string(), "foo/1.0".to_string()));

    for i in 0..header_fields.len() {
        let &(ref name, _) = header_fields.get(i)
            .unwrap();

        header_map.insert(name.to_lowercase(), i);
    }

    let header = ResponseHeader {
        version:    "1.0".to_string(),
        code:       200,
        line:       "OK".to_string(),
        headers:    header_fields,
        header_map: header_map
    };

    let body = "hello".as_bytes()
        .to_vec();

    let response = Response::new(header, body);

    let expected = "HTTP/1.0 200 OK\r\n".to_string()
        + "Server: foo/1.0\r\n"
        + "\r\n"
        + "hello";

    let msg = format!("{}", response);

    assert_eq!(expected, msg);

    let mut rbuilder = ResponseBuilder::new();

    {
        let mut parser = ResponseParser::new(&mut rbuilder, 4096, 256);

        parser.add(expected.as_bytes())
            .unwrap();
    }

    let response = rbuilder.response()
        .unwrap();

    assert_eq!(response.header.code, 200);
    assert_eq!(response.header.line, "OK");
    assert_eq!(response.header.get_str("server"), Some("foo/1.0"));
    assert_eq!(response.body, b"hello");
}
