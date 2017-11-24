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

pub mod sdp;

use std::io;
use std::fmt;

use std::error::Error as ErrorTrait;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use net;

use net::nhttp::generic;

use net::nhttp::generic::HeaderField;
use net::nhttp::generic::ClientCodec as GenericClientCodec;
use net::nhttp::generic::Request as GenericRequest;
use net::nhttp::generic::Response as GenericResponse;
use net::nhttp::generic::RequestBuilder as GenericRequestBuilder;

use net::url::Url;

use bytes::BytesMut;

use futures::{Future, Poll, Sink, Stream};

use tokio_core::net::TcpStream;
use tokio_core::reactor::Handle as TokioHandle;

use tokio_io::AsyncRead;
use tokio_io::codec::{Decoder, Encoder};

/// RTSP codec error.
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

/// RTSP method.
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Method {
    OPTIONS,
    DESCRIBE,
    ANNOUNCE,
    SETUP,
    PLAY,
    PAUSE,
    TEARDOWN,
    GET_PARAMETER,
    SET_PARAMETER,
    REDIRECT,
    RECORD,
}

impl Method {
    /// Get method name.
    fn name(self) -> &'static str {
        match self {
            Method::OPTIONS       => "OPTIONS",
            Method::DESCRIBE      => "DESCRIBE",
            Method::ANNOUNCE      => "ANNOUNCE",
            Method::SETUP         => "SETUP",
            Method::PLAY          => "PLAY",
            Method::PAUSE         => "PAUSE",
            Method::TEARDOWN      => "TEARDOWN",
            Method::GET_PARAMETER => "GET_PARAMETER",
            Method::SET_PARAMETER => "SET_PARAMETER",
            Method::REDIRECT      => "REDIRECT",
            Method::RECORD        => "RECORD",
        }
    }
}

/// Valid URL schemes.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Scheme {
    RTSP,
}

impl Scheme {
    /// Get default port for this URL scheme.
    fn default_port(self) -> u16 {
        match self {
            Scheme::RTSP  => 554,
        }
    }
}

impl FromStr for Scheme {
    type Err = Error;

    fn from_str(method: &str) -> Result<Scheme, Error> {
        match &method.to_lowercase() as &str {
            "rtsp"  => Ok(Scheme::RTSP),
            _ => Err(Error::from("invalid URL scheme")),
        }
    }
}

/// RTSP request.
#[derive(Clone)]
pub struct Request {
    scheme:           Scheme,
    host:             String,
    port:             u16,
    inner:            GenericRequest,
    max_line_length:  usize,
    max_header_lines: usize,
}

impl Request {
    /// Send the request and return a future response
    pub fn send(self, handle: &TokioHandle) -> Result<FutureResponse, Error> {
        let addr = net::utils::get_socket_address((self.host.as_ref(), self.port))
            .map_err(|_| Error::from("unable to resolve a given socket address"))?;

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

        // TODO: add timeout

        let response = FutureResponse::new(response);

        Ok(response)
    }
}

/// RTSP request builder.
pub struct RequestBuilder {
    scheme:           Scheme,
    host:             String,
    port:             u16,
    inner:            GenericRequestBuilder,
    max_line_length:  usize,
    max_header_lines: usize,
}

impl RequestBuilder {
    /// Create a new RTSP request builder.
    pub fn new(method: Method, url: &str) -> Result<RequestBuilder, Error> {
        let url = Url::from_str(url)
            .map_err(|_| Error::from("malformed URL"))?;

        let scheme = Scheme::from_str(url.scheme())?;

        let host = url.host();
        let port = url.port()
            .unwrap_or(scheme.default_port());

        let inner = GenericRequestBuilder::new(
            "RTSP",
            "1.0",
            method.name(),
            url.as_ref());

        let builder = RequestBuilder {
            scheme:           scheme,
            host:             host.to_string(),
            port:             port,
            inner:            inner,
            max_line_length:  4096,
            max_header_lines: 1024,
        };

        Ok(builder)
    }

    /// Create a new OPTIONS request.
    pub fn options(url: &str) -> Result<RequestBuilder, Error> {
        RequestBuilder::new(Method::OPTIONS, url)
    }

    /// Create a new DESCRIBE request.
    pub fn describe(url: &str) -> Result<RequestBuilder, Error> {
        RequestBuilder::new(Method::DESCRIBE, url)
    }

    /// Add a given header field.
    pub fn add_header_field(mut self, field: HeaderField) -> RequestBuilder {
        self.inner = self.inner.add_header_field(field);
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
            max_line_length:  self.max_line_length,
            max_header_lines: self.max_header_lines,
        }
    }
}

/// RTSP response.
pub struct Response {
    inner: GenericResponse,
}

impl Response {
    /// Create a new RTSP response from a given generic response.
    fn new(response: GenericResponse) -> Result<Response, Error> {
        {
            let header = response.header();
            let protocol = header.protocol();
            let version = header.version();

            if protocol != "RTSP" {
                return Err(Error::from("invalid protocol"));
            }

            if version != "1.0" {
                return Err(Error::from("unsupported RTSP version"));
            }
        }

        let response = Response {
            inner: response,
        };

        Ok(response)
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

/// RTSP client codec.
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
