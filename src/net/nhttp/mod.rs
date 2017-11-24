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

pub mod generic;

use std::io;
use std::fmt;

use std::error::Error as ErrorTrait;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::time::Duration;

use net;

use net::url::Url;

use timer::DEFAULT_TIMER;

use self::generic::HeaderField;
use self::generic::ClientCodec as GenericClientCodec;
use self::generic::Request as GenericRequest;
use self::generic::Response as GenericResponse;
use self::generic::RequestBuilder as GenericRequestBuilder;

use bytes::BytesMut;

use futures::{Future, Poll, Sink, Stream};

use tokio_core::net::TcpStream;
use tokio_core::reactor::Handle as TokioHandle;

use tokio_io::AsyncRead;
use tokio_io::codec::{Decoder, Encoder};

use tokio_timer::TimeoutError;

/// HTTP codec error.
#[derive(Debug, Clone)]
pub struct Error {
    msg: String,
}

impl ErrorTrait for Error {
    fn description(&self) -> &str {
        &self.msg
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        f.write_str(self.description())
    }
}

impl From<String> for Error {
    fn from(msg: String) -> Error {
        Error { msg: msg }
    }
}

impl<'a> From<&'a str> for Error {
    fn from(msg: &'a str) -> Error {
        Error::from(msg.to_string())
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::from(format!("IO error: {}", err))
    }
}

impl From<generic::Error> for Error {
    fn from(err: generic::Error) -> Error {
        Error::from(err.description())
    }
}

impl<T> From<TimeoutError<T>> for Error {
    fn from(err: TimeoutError<T>) -> Error {
        Error::from(format!("request timeout: {}", err))
    }
}

/// HTTP method.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Method {
    OPTIONS,
    HEAD,
    GET,
    POST,
    PUT,
    DELETE,
    TRACE,
    CONNECT,
}

impl Method {
    /// Get method name.
    fn name(self) -> &'static str {
        match self {
            Method::OPTIONS => "OPTIONS",
            Method::HEAD    => "HEAD",
            Method::GET     => "GET",
            Method::POST    => "POST",
            Method::PUT     => "PUT",
            Method::DELETE  => "DELETE",
            Method::TRACE   => "TRACE",
            Method::CONNECT => "CONNECT",
        }
    }
}

/// Valid URL schemes.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Scheme {
    HTTP,
    HTTPS,
}

impl Scheme {
    /// Get default port for this URL scheme.
    fn default_port(self) -> u16 {
        match self {
            Scheme::HTTP  => 80,
            Scheme::HTTPS => 443,
        }
    }
}

impl FromStr for Scheme {
    type Err = Error;

    fn from_str(method: &str) -> Result<Scheme, Error> {
        match &method.to_lowercase() as &str {
            "http"  => Ok(Scheme::HTTP),
            "https" => Ok(Scheme::HTTPS),
            _ => Err(Error::from("invalid URL scheme")),
        }
    }
}

/// HTTP request.
#[derive(Clone)]
pub struct Request {
    scheme:           Scheme,
    host:             String,
    port:             u16,
    inner:            GenericRequest,
    timeout:          Option<Duration>,
    max_line_length:  usize,
    max_header_lines: usize,
}

impl Request {
    /// Send the request and return a future response
    pub fn send(self, handle: &TokioHandle) -> Result<FutureResponse, Error> {
        // TODO: add TLS layer in case of HTTPS scheme

        let addr = net::utils::get_socket_address((self.host.as_ref(), self.port))
            .map_err(|_| Error::from("unable to resolve a given socket address"))?;

        let timeout = self.timeout.clone();

        // single request-response cycle
        let response = TcpStream::connect(&addr, &handle)
            .map_err(|err| Error::from(err))
            .and_then(|stream| {
                stream.framed(ClientCodec::new(self.max_line_length, self.max_header_lines))
                    .send(self)
                    .map_err(|err| Error::from(err))
                    .and_then(|stream| {
                        stream.into_future()
                            .map_err(|(err, _)| err)
                            .and_then(|(response, _)| {
                                response.ok_or(Error::from("server closed connection unexpectedly"))
                            })
                    })
            });

        if let Some(timeout) = timeout {
            let response = DEFAULT_TIMER
                .timeout(response, timeout);

            Ok(FutureResponse::new(response))
        } else {
            Ok(FutureResponse::new(response))
        }
    }
}

/// HTTP request builder.
pub struct RequestBuilder {
    scheme:           Scheme,
    host:             String,
    port:             u16,
    inner:            GenericRequestBuilder,
    timeout:          Option<Duration>,
    max_line_length:  usize,
    max_header_lines: usize,
}

impl RequestBuilder {
    /// Create a new HTTP request builder.
    pub fn new(method: Method, url: &str) -> Result<RequestBuilder, Error> {
        let url = Url::from_str(url)
            .map_err(|_| Error::from("malformed URL"))?;

        let scheme = Scheme::from_str(url.scheme())?;

        let host = url.host();
        let port = url.port()
            .unwrap_or(scheme.default_port());

        let mut path = url.path()
            .to_string();

        if let Some(query) = url.query() {
            path += query;
        }

        let inner = GenericRequestBuilder::new(
            "HTTP",
            "1.0",
            method.name(),
            &path);

        let builder = RequestBuilder {
            scheme:           scheme,
            host:             host.to_string(),
            port:             port,
            inner:            inner,
            timeout:          Some(Duration::from_secs(20)),
            max_line_length:  4096,
            max_header_lines: 1024,
        };

        Ok(builder)
    }

    /// Create a new GET request.
    pub fn get(url: &str) -> Result<RequestBuilder, Error> {
        RequestBuilder::new(Method::GET, url)
    }

    /// Set protocol version.
    pub fn set_version(mut self, version: &str) -> RequestBuilder {
        self.inner = self.inner.set_version(version);
        self
    }

    /// Add a given header field.
    pub fn add_header_field(mut self, field: HeaderField) -> RequestBuilder {
        self.inner = self.inner.add_header_field(field);
        self
    }

    /// Set request timeout.
    pub fn set_request_timeout(mut self, timeout: Option<Duration>) -> RequestBuilder {
        self.timeout = timeout;
        self
    }

    /// Set maximum length of a single line accepted by the response parser.
    pub fn set_max_line_length(mut self, max_length: usize) -> RequestBuilder {
        self.max_line_length = max_length;
        self
    }

    /// Set maximum number of header lines accepted by the response parser.
    pub fn set_max_header_lines(mut self, max_lines: usize) -> RequestBuilder {
        self.max_header_lines = max_lines;
        self
    }

    /// Build request.
    pub fn build(self) -> Request {
        Request {
            scheme:           self.scheme,
            host:             self.host,
            port:             self.port,
            inner:            self.inner.build(),
            timeout:          self.timeout,
            max_line_length:  self.max_line_length,
            max_header_lines: self.max_header_lines,
        }
    }
}

/// HTTP response.
pub struct Response {
    inner: GenericResponse,
}

impl Response {
    /// Create a new HTTP response from a given generic response.
    fn new(response: GenericResponse) -> Result<Response, Error> {
        {
            let header = response.header();
            let protocol = header.protocol();
            let version = header.version();

            if protocol != "HTTP" {
                return Err(Error::from("invalid protocol"));
            }

            if version != "1.0" && version != "1.1" {
                return Err(Error::from("unsupported HTTP version"));
            }
        }

        let response = Response {
            inner: response,
        };

        Ok(response)
    }

    /// Get protocol version.
    pub fn version(&self) -> &str {
        self.inner.header()
            .version()
    }

    /// Get status code.
    pub fn status_code(&self) -> u16 {
        self.inner.header()
            .status_code()
    }

    /// Get status line.
    pub fn status_line(&self) -> &str {
        self.inner.header()
            .status_line()
    }

    /// Get response body.
    pub fn body(&self) -> &[u8] {
        self.inner.body()
    }

    /// Get header fields corresponding to a given name.
    pub fn get_header_fields(&self, name: &str) -> &[HeaderField] {
        self.inner.header()
            .get_header_fields(name)
    }

    /// Get last header field of a given name.
    pub fn get_header_field(&self, name: &str) -> Option<&HeaderField> {
        self.inner.header()
            .get_header_field(name)
    }
}

/// Future response. This struct implements the Futere trait yielding Response.
pub struct FutureResponse {
    inner: Box<Future<Item=Response, Error=Error>>,
}

impl FutureResponse {
    /// Create a new future response.
    fn new<F>(future: F) -> FutureResponse
        where F: 'static + Future<Item=Response, Error=Error> {
        FutureResponse {
            inner: Box::new(future),
        }
    }
}

impl Future for FutureResponse {
    type Item = Response;
    type Error = Error;

    fn poll(&mut self) -> Poll<Response, Error> {
        self.inner.poll()
    }
}

/// HTTP client codec.
struct ClientCodec {
    inner: GenericClientCodec,
}

impl ClientCodec {
    /// Create a new codec instance.
    fn new(max_line_length: usize, max_header_lines: usize) -> ClientCodec {
        ClientCodec {
            inner: GenericClientCodec::new(max_line_length, max_header_lines),
        }
    }
}

impl Decoder for ClientCodec {
    type Item = Response;
    type Error = Error;

    fn decode(&mut self, data: &mut BytesMut) -> Result<Option<Response>, Error> {
        if let Some(response) = self.inner.decode(data)? {
            // try to parse a given generic response
            let response = Response::new(response)?;

            Ok(Some(response))
        } else {
            Ok(None)
        }
    }
}

impl Encoder for ClientCodec {
    type Item = Request;
    type Error = io::Error;

    fn encode(&mut self, message: Request, buffer: &mut BytesMut) -> Result<(), io::Error> {
        self.inner.encode(message.inner, buffer)
    }
}
