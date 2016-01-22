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
use std::num;
use std::result;
use std::str;

use std::error::Error;
use std::str::FromStr;
use std::net::SocketAddr;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::fmt::{Display, Formatter, Debug};

use mio;

use regex::Regex;

use mio::{EventLoop, Handler, Token, EventSet, PollOpt};
use mio::tcp::TcpStream;

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
        RtspError { msg: msg.to_string() }
    }
}

impl From<io::Error> for RtspError {
    fn from(err: io::Error) -> RtspError {
        RtspError::from(format!("IO error: {}", err.description()))
    }
}

impl From<mio::TimerError> for RtspError {
    fn from(_: mio::TimerError) -> RtspError {
        RtspError::from(format!("timer error"))
    }
}

impl From<num::ParseIntError> for RtspError {
    fn from(_: num::ParseIntError) -> RtspError {
        RtspError::from("integer parsing error")
    }
}

impl From<str::Utf8Error> for RtspError {
    fn from(_: str::Utf8Error) -> RtspError {
        RtspError::from("UTF-8 parsing error")
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
    method:  Method,
    host:    SocketAddr,
    path:    String,
    headers: Vec<Header>,
}

impl Request {
    /// Create a new request.
    fn new(method: Method, host: &SocketAddr, path: &str) -> Request {
        Request {
            method:  method,
            host:    host.clone(),
            path:    path.to_string(),
            headers: Vec::new()
        }
    }
    
    /// Add a new header field into the request.
    fn add_header<N, V>(mut self, header: (N, V)) -> Request
        where N: ToString, V: ToString {
        let (name, value) = header;
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
}

impl Display for Request {
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        try!(f.write_str(&format!("{} rtsp://{}{} RTSP/1.0\r\n", 
            self.method.name(), &self.host, &self.path)));
        for &(ref name, ref val) in &self.headers {
            try!(f.write_str(&format!("{}: {}\r\n", name, val)));
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
        try!(Display::fmt(&self.header, f));
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
        try!(f.write_str(&format!("RTSP/1.0 {} {}\r\n", 
            self.code, &self.line)));
        for &(ref name, ref value) in &self.headers {
            try!(f.write_str(&format!("{}: {}\r\n", name, value)));
        }
        
        f.write_str("\r\n")
    }
}

/// Header or continuation (convenience enum for header field parsing).
enum HeaderCont {
    Header(Header),
    Cont(String),
    Empty,
}

/// RTSP response header parser.
struct ResponseHeaderParser {
    status_re: Regex,
    header_re: Regex,
    cont_re:   Regex,
}

impl ResponseHeaderParser {
    /// Create a new response header parser.
    fn new() -> ResponseHeaderParser {
        ResponseHeaderParser {
            status_re: Regex::new(r"^RTSP/1.0 (\d+) (.*)$").unwrap(),
            header_re: Regex::new(r"^([^ :]+):\s*(.*)$").unwrap(),
            cont_re:   Regex::new(r"^\s+(.*)$").unwrap(),
        }
    }
    
    /// Parse a given response header string.
    fn parse(&self, s: &str) -> Result<ResponseHeader> {
        let mut lines = s.split("\r\n");
        
        let mut headers = Vec::new();
        let status_code;
        let status;
        
        if let Some(line) = lines.next() {
            let (sc, s) = try!(self.parse_status_line(line));
            status_code = sc;
            status      = s;
        } else {
            return Err(RtspError::from("RTSP status line is missing"));
        }
        
        for line in lines {
            match try!(self.parse_header_line(line)) {
                HeaderCont::Empty     => break,
                HeaderCont::Header(h) => headers.push(h),
                HeaderCont::Cont(c)   => {
                    if let Some((name, val)) = headers.pop() {
                        headers.push((name, val + &c));
                    } else {
                        return Err(RtspError::from(
                            "first RTSP header cannot be continuation"));
                    }
                },
            }
        }
        
        Ok(ResponseHeader::new(status_code, status, headers))
    }
    
    /// Parse RTSP status line.
    fn parse_status_line(&self, line: &str) -> Result<(i32, String)> {
        if let Some(caps) = self.status_re.captures(line) {
            let status_code = caps.at(1).unwrap();
            let status      = caps.at(2).unwrap();
            let sc_int      = try!(i32::from_str(status_code));
            Ok((sc_int, status.to_string()))
        } else {
            Err(RtspError::from("invalid RTSP status line"))
        }
    }
    
    /// Parse RTSP header line.
    fn parse_header_line(&self, line: &str) -> Result<HeaderCont> {
        if line.is_empty() {
            Ok(HeaderCont::Empty)
        } else if let Some(caps) = self.header_re.captures(line) {
            let name  = caps.at(1).unwrap();
            let value = caps.at(2).unwrap();
            Ok(HeaderCont::Header((name.to_string(), value.to_string())))
        } else if let Some(caps) = self.cont_re.captures(line) {
            let value = caps.at(1).unwrap();
            Ok(HeaderCont::Cont(value.to_string()))
        } else {
            Err(RtspError::from("invalid RTSP header line"))
        }
    }
}

/// RTSP response parser.
struct ResponseParser {
    header_parser: ResponseHeaderParser,
    buffer:        Vec<u8>,
    buffer_limit:  usize,
    last_line:     usize,
    header:        Option<ResponseHeader>,
    header_len:    usize,
    expected:      usize,
}

impl ResponseParser {
    /// Create a new response parser.
    fn new(buffer_limit: usize) -> ResponseParser {
        ResponseParser {
            header_parser: ResponseHeaderParser::new(),
            buffer:        Vec::new(),
            buffer_limit:  buffer_limit,
            last_line:     0,
            header:        None,
            header_len:    0,
            expected:      0
        }
    }
    
    /// Check if the last message is complete.
    fn is_complete(&self) -> bool {
        self.header.is_some() && self.expected == 0
    }
    
    /// Get last response.
    fn response(&self) -> Option<Response> {
        let header = if let Some(ref header) = self.header {
            header.clone()
        } else {
            return None;
        };
        
        let body = if self.is_complete() {
            self.buffer[self.header_len..].to_vec()
        } else {
            return None;
        };
        
        Some(Response::new(header, body))
    }
    
    /// Clear the current message.
    fn clear(&mut self) {
        self.buffer.clear();
        self.last_line  = 0;
        self.header     = None;
        self.header_len = 0;
        self.expected   = 0;
    }
    
    /// Process a given chunk of data and return the number of bytes used.
    fn add(&mut self, chunk: &[u8]) -> Result<usize> {
        let mut pos = 0;
        
        while pos < chunk.len() && 
            (self.header.is_none() || self.expected > 0) {
            if self.header.is_none() {
                pos += try!(self.read_header(&chunk[pos..]));
                if let Some(ref header) = self.header {
                    if let Some(len) = header.get::<usize>("Content-Length") {
                        self.expected = len;
                    } else {
                        self.expected = 0;
                    }
                }
            } else if self.expected > 0 {
                let end = if (pos + self.expected) > chunk.len() {
                    chunk.len()
                } else {
                    pos + self.expected
                };
                // TODO: use resize (as soon as it is available) and memcpy 
                // here as it is more effective
                self.buffer.extend(chunk[pos..end].iter());
                self.expected -= end - pos;
                pos = end;
            }
        }
        
        Ok(pos)
    }
    
    /// Read RTSP header.
    fn read_header(&mut self, chunk: &[u8]) -> Result<usize> {
        let mut pos = 0;
        
        while self.header.is_none() && pos < chunk.len() {
            let (complete, used) = try!(self.read_line(&chunk[pos..]));
            
            pos += used;
            
            if complete {
                let line_len = self.buffer.len() - self.last_line;
                self.last_line = self.buffer.len();
                
                if line_len == 2 {
                    let header_str = try!(str::from_utf8(&self.buffer));
                    let header     = try!(self.header_parser.parse(header_str));
                    self.header    = Some(header);
                }
            }
        }
        
        Ok(pos)
    }
    
    /// Read next line.
    fn read_line(&mut self, chunk: &[u8]) -> Result<(bool, usize)> {
        let mut complete = false;
        let mut pos = 0;
        
        let mut last = match self.buffer[self.last_line..].last() {
            Some(c) => Some(*c),
            None    => None
        };
        
        while !complete && pos < chunk.len() {
            if self.buffer.len() >= self.buffer_limit {
                return Err(RtspError::from(
                    "unable to parse RTSP response, buffer limit exceeded"));
            }
            
            let c = chunk[pos];
            self.buffer.push(c);
            pos += 1;
            
            if let Some(last) = last {
                if last == 0x0d && c == 0x0a {
                    complete = true;
                }
            }
            
            last = Some(c);
        }
        
        Ok((complete, pos))
    }
}

/// RTSP client.
pub struct Client {
    connection: ClientHandler,
    event_loop: EventLoop<ClientHandler>,
    endpoint:   SocketAddr,
}

impl Client {
    /// Create a new RTSP client for a given remote service.
    pub fn new(addr: SocketAddr) -> Result<Client> {
        let stream         = try!(TcpStream::connect(&addr));
        let mut event_loop = try!(EventLoop::new());
        let connection     = try!(ClientHandler::new(stream, &mut event_loop));
        let client = Client {
            connection: connection,
            event_loop: event_loop,
            endpoint:   addr
        };
        
        Ok(client)
    }
    
    /// Set timeout for read and write operations.
    pub fn set_timeout(&mut self, ms: Option<u64>) {
        self.connection.set_timeout(ms)
    }
    
    /// Send OPTIONS command.
    pub fn options(&mut self) -> Result<Response> {
        let request = Request::new(Method::OPTIONS, &self.endpoint, "/")
            .add_header(("CSeq", 1));
        
        try!(self.connection.send(&request, &mut self.event_loop));
        
        self.connection.read(&mut self.event_loop)
    }
    
    /// Send DESCRIBE command.
    pub fn describe(&mut self, path: &str) -> Result<Response> {
        let request = Request::new(Method::DESCRIBE, &self.endpoint, path)
            .add_header(("CSeq", 1));
        
        try!(self.connection.send(&request, &mut self.event_loop));
        
        self.connection.read(&mut self.event_loop)
    }
}

/// RTSP client connection handler.
struct ClientHandler {
    stream:   TcpStream,
    timeout:  Option<u64>,
    buffer:   Box<[u8]>,
    buffered: usize,
    read:     usize,
    parser:   ResponseParser,
    request:  Option<Vec<u8>>,
    sent:     usize,
    err:      Option<RtspError>,
}

impl ClientHandler {
    /// Create a new connection handler.
    fn new(
        stream: TcpStream, 
        event_loop: &mut EventLoop<Self>) -> Result<ClientHandler> {
        let mut events = EventSet::all();
        events.remove(EventSet::readable());
        events.remove(EventSet::writable());
        try!(event_loop.register(&stream, Token(0), 
            events, PollOpt::level()));
        
        let res = ClientHandler {
            stream:   stream,
            timeout:  None,
            buffer:   Box::new([0u8; 4096]),
            buffered: 0,
            read:     0,
            parser:   ResponseParser::new(4096),
            request:  None,
            sent:     0,
            err:      None
        };
        
        Ok(res)
    }
    
    /// Set send/receive timeout.
    fn set_timeout(&mut self, ms: Option<u64>) {
        self.timeout = ms;
    }
    
    /// Send a given request.
    fn send(
        &mut self, 
        request: &Request, 
        event_loop: &mut EventLoop<Self>) -> Result<()> {
        self.init(Some(request));
        
        let mut events = EventSet::all();
        events.remove(EventSet::readable());
        try!(event_loop.reregister(&self.stream, Token(0), 
            events, PollOpt::level()));
        
        let timeout = match self.timeout {
            Some(ms) => Some(try!(event_loop.timeout_ms(0, ms))),
            None => None
        };
        
        try!(event_loop.run(self));
        
        if let Some(timeout) = timeout {
            event_loop.clear_timeout(timeout);
        }
        
        if let Some(ref err) = self.err {
            Err(err.clone())
        } else {
            Ok(())
        }
    }
    
    /// Read RTSP response.
    fn read(&mut self, event_loop: &mut EventLoop<Self>) -> Result<Response> {
        self.init(None);
        
        let mut events = EventSet::all();
        events.remove(EventSet::writable());
        try!(event_loop.reregister(&self.stream, Token(0), 
            events, PollOpt::level()));
        
        let timeout = match self.timeout {
            Some(ms) => Some(try!(event_loop.timeout_ms(0, ms))),
            None => None
        };
        
        try!(event_loop.run(self));
        
        if let Some(timeout) = timeout {
            event_loop.clear_timeout(timeout);
        }
        
        if let Some(ref err) = self.err {
            Err(err.clone())
        } else if let Some(response) = self.parser.response() {
            Ok(response)
        } else {
            Err(RtspError::from("unable to get server response"))
        }
    }
    
    /// Initialize handler.
    fn init(&mut self, request: Option<&Request>) {
        self.parser.clear();
        
        self.sent     = 0;
        self.err      = None;
        
        self.request = match request {
            None          => None,
            Some(request) => {
                let request_data = format!("{}", request);
                Some(request_data.into_bytes())
            }
        };
    }
    
    /// Check socket events.
    fn socket_ready(&mut self, event_set: EventSet) -> Result<bool> {
        let read_res = if self.request.is_none() && event_set.is_readable() {
            try!(self.read_ready())
        } else {
            false
        };
        
        let write_res = if self.request.is_some() && event_set.is_writable() {
            try!(self.write_ready())
        } else {
            false
        };
        
        if event_set.is_error() {
            let socket_err = self.stream.take_socket_error();
            Err(RtspError::from(socket_err.unwrap_err()))
        } else if event_set.is_hup() {
            Ok(false)
        } else {
            Ok(read_res || write_res)
        }
    }
    
    /// Check read event.
    fn read_ready(&mut self) -> Result<bool> {
        // process any leftovers
        let read = try!(self.process_buffer());
        
        // check if we still need to read anything
        if read {
            self.buffered = try!(self.stream.read(&mut *self.buffer));
            self.read     = 0;
            
            Ok(try!(self.process_buffer()))
        } else {
            Ok(false)
        }
    }
    
    /// Process buffered data.
    fn process_buffer(&mut self) -> Result<bool> {
        while self.read < self.buffered && !self.parser.is_complete() {
            let buffer = &self.buffer[self.read..self.buffered];
            self.read += try!(self.parser.add(buffer));
        }
        
        Ok(!self.parser.is_complete())
    }
    
    /// Check write event.
    fn write_ready(&mut self) -> Result<bool> {
        let mut discard = false;
        
        if let Some(ref request) = self.request {
            self.sent += try!(self.stream.write(&request[self.sent..]));
            if self.sent >= request.len() {
                discard = true;
            }
        }
        
        if discard {
            self.request = None;
        }
        
        Ok(self.request.is_some())
    }
}

impl Handler for ClientHandler {
    type Timeout = u32;
    type Message = ();
    
    fn ready(
        &mut self, 
        event_loop: &mut EventLoop<Self>, 
        _: Token, 
        event_set: EventSet) {
        match self.socket_ready(event_set) {
            Ok(true)  => (),
            Ok(false) => event_loop.shutdown(),
            Err(err)  => {
                self.err = Some(err);
                event_loop.shutdown();
            }
        }
    }
    
    fn timeout(&mut self, event_loop: &mut EventLoop<Self>, _: u32) {
        self.err = Some(RtspError::from("connection timeout"));
        event_loop.shutdown();
    }
}

#[cfg(test)]
use std::net::ToSocketAddrs;

#[cfg(test)]
#[test]
fn test_rtsp_request() {
    let addr = "127.0.0.1:554".to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();
    
    let request = Request::new(Method::DESCRIBE, &addr, "/foo")
        .add_header(("CSeq", 1))
        .add_header(("Connection", "close"));
    
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
    
    let header = ResponseHeader::new(200, "OK".to_string(), header_fields);
    let body   = "hello".as_bytes().to_vec();
    
    let response = Response::new(header, body);
    
    let expected = "RTSP/1.0 200 OK\r\n".to_string()
        + "CSeq: 1\r\n"
        + "\r\n"
        + "hello";
    
    let msg = format!("{}", response);
    
    assert_eq!(expected, msg);
    
    let parser   = ResponseHeaderParser::new();
    let response = parser.parse(&expected).unwrap();
    
    assert_eq!(response.code, 200);
    assert_eq!(response.line, "OK");
    assert_eq!(response.get("cseq"), Some(1));
}
