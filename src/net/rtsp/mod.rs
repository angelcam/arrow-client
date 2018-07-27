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
use std::time::{Instant, Duration};

use net;

use net::http::generic;

use net::http::generic::FixedSizeBodyDecoder;
use net::http::generic::HeaderField;
use net::http::generic::Response as GenericResponse;
use net::http::generic::ResponseHeader as GenericResponseHeader;
use net::http::generic::ResponseHeaderDecoder as GenericResponseHeaderDecoder;
use net::http::generic::Request as GenericRequest;
use net::http::generic::RequestBuilder as GenericRequestBuilder;

use net::url::Url;

use bytes::BytesMut;

use futures::{Future, IntoFuture, Poll, Sink, Stream};

use tokio::net::TcpStream;
use tokio::timer::Deadline;

use tokio_codec::{Decoder, Encoder};

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
    host:                 String,
    port:                 u16,
    inner:                GenericRequestBuilder,
    timeout:              Option<Duration>,
    max_line_length:      usize,
    max_header_lines:     usize,
    ignore_response_body: bool,
}

impl Request {
    /// Create a new RTSP request.
    pub fn new(method: Method, url: &str, ignore_response_body: bool) -> Result<Request, Error> {
        let url = Url::from_str(url)
            .map_err(|_| Error::from("malformed URL"))?;

        let scheme = Scheme::from_str(url.scheme())?;

        let host = url.host();
        let port = url.port()
            .unwrap_or(scheme.default_port());

        let app_version = env!("CARGO_PKG_VERSION");

        let uagent = format!("ArrowClient/{}", app_version);

        let inner = GenericRequestBuilder::new(
                "RTSP",
                "1.0",
                method.name(),
                url.as_ref())
            .set_header_field(("CSeq", 1))
            .set_header_field(("User-Agent", uagent));

        let builder = Request {
            host:                 host.to_string(),
            port:                 port,
            inner:                inner,
            timeout:              Some(Duration::from_secs(20)),
            max_line_length:      4096,
            max_header_lines:     1024,
            ignore_response_body: ignore_response_body,
        };

        Ok(builder)
    }

    /// Create a new OPTIONS request.
    pub fn options(url: &str) -> Result<Request, Error> {
        Request::new(Method::OPTIONS, url, true)
    }

    /// Create a new DESCRIBE request.
    pub fn describe(url: &str) -> Result<Request, Error> {
        let request = Request::new(Method::DESCRIBE, url, false)?
            .set_header_field(("Accept", "application/sdp"));

        Ok(request)
    }

    /// Set a given header field.
    pub fn set_header_field<T>(mut self, field: T) -> Request
        where HeaderField: From<T> {
        self.inner = self.inner.set_header_field(field);
        self
    }

    /// Set request timeout.
    pub fn set_request_timeout(mut self, timeout: Option<Duration>) -> Request {
        self.timeout = timeout;
        self
    }

    /// Set maximum length of a single line accepted by the response parser.
    pub fn set_max_line_length(mut self, max_length: usize) -> Request {
        self.max_line_length = max_length;
        self
    }

    /// Set maximum number of header lines accepted by the response parser.
    pub fn set_max_header_lines(mut self, max_lines: usize) -> Request {
        self.max_header_lines = max_lines;
        self
    }

    /// Send the request and return a future response
    pub fn send(self) -> FutureResponse {
        let addr = net::utils::get_socket_address((self.host.as_ref(), self.port))
            .map_err(|_| Error::from("unable to resolve a given socket address"));

        if let Err(err) = addr {
            return FutureResponse::new(Err(err));
        }

        let timeout = self.timeout.clone();

        let codec = ClientCodec::new(
            self.max_line_length,
            self.max_header_lines,
            self.ignore_response_body);

        // single request-response cycle
        let response = TcpStream::connect(&addr.unwrap())
            .map_err(|err| Error::from(err))
            .and_then(move |stream| {
                codec.framed(stream)
                    .send(self.inner.build())
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
            let response = Deadline::new(response, Instant::now() + timeout)
                .map_err(|err| {
                    if err.is_elapsed() {
                        Error::from("request timeout")
                    } else if let Some(inner) = err.into_inner() {
                        inner
                    } else {
                        Error::from("timer error")
                    }
                });

            FutureResponse::new(response)
        } else {
            FutureResponse::new(response)
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

    /// Get value of the last header field with a given name.
    pub fn get_header_field_value(&self, name: &str) -> Option<&str> {
        self.inner.header()
            .get_header_field_value(name)
    }
}

/// Future response. This struct implements the Futere trait yielding Response.
pub struct FutureResponse {
    inner: Box<Future<Item=Response, Error=Error>>,
}

impl FutureResponse {
    /// Create a new future response.
    fn new<F>(future: F) -> FutureResponse
        where F: 'static + IntoFuture<Item=Response, Error=Error> {
        FutureResponse {
            inner: Box::new(future.into_future()),
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
    hdecoder:             GenericResponseHeaderDecoder,
    bdecoder:             Option<FixedSizeBodyDecoder>,
    header:               Option<GenericResponseHeader>,
    ignore_response_body: bool,
}

impl ClientCodec {
    /// Create a new RTSP client codec.
    fn new(
        max_line_length: usize,
        max_header_lines: usize,
        ignore_response_body: bool) -> ClientCodec {
        let hdecoder = GenericResponseHeaderDecoder::new(
            max_line_length,
            max_header_lines);

        ClientCodec {
            hdecoder:             hdecoder,
            bdecoder:             None,
            header:               None,
            ignore_response_body: ignore_response_body,
        }
    }
}

impl Decoder for ClientCodec {
    type Item = Response;
    type Error = Error;

    fn decode(&mut self, data: &mut BytesMut) -> Result<Option<Response>, Error> {
        if self.header.is_none() {
            if let Some(header) = self.hdecoder.decode(data)? {
                let bdecoder;

                if let Some(clength) = header.get_header_field("content-length") {
                    let clength = clength.value()
                        .ok_or(Error::from("missing Content-Length value"))?;
                    let clength = usize::from_str(clength)
                        .map_err(|_| Error::from("unable to decode Content-Length"))?;

                    bdecoder = FixedSizeBodyDecoder::new(clength, self.ignore_response_body);
                } else {
                    bdecoder = FixedSizeBodyDecoder::new(0, self.ignore_response_body);
                }

                self.bdecoder = Some(bdecoder);
                self.header = Some(header);
            }
        }

        if let Some(mut bdecoder) = self.bdecoder.take() {
            if let Some(body) = bdecoder.decode(data)? {
                let header = self.header.take()
                    .expect("header is missing");

                let response = GenericResponse::new(header, body);
                let response = Response::new(response)?;

                return Ok(Some(response));
            }

            self.bdecoder = Some(bdecoder);
        }

        Ok(None)
    }

    fn decode_eof(&mut self, data: &mut BytesMut) -> Result<Option<Response>, Error> {
        while !data.is_empty() {
            let res = self.decode(data)?;

            if res.is_some() {
                return Ok(res);
            }
        }

        if let Some(mut bdecoder) = self.bdecoder.take() {
            if let Some(body) = bdecoder.decode_eof(data)? {
                let header = self.header.take()
                    .expect("header is missing");

                let response = GenericResponse::new(header, body);
                let response = Response::new(response)?;

                return Ok(Some(response));
            }

            self.bdecoder = Some(bdecoder);
        }

        Ok(None)
    }
}

impl Encoder for ClientCodec {
    type Item = GenericRequest;
    type Error = io::Error;

    fn encode(&mut self, message: GenericRequest, buffer: &mut BytesMut) -> Result<(), io::Error> {
        let header = format!("{}", message.header());
        let body = message.body();

        buffer.extend_from_slice(header.as_bytes());
        buffer.extend_from_slice(body);

        Ok(())
    }
}
