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

pub mod generic;

use std::{fmt::Write, io, str::FromStr, time::Duration};

use bytes::BytesMut;
use futures::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_util::codec::{Decoder, Encoder};
use ttpkit_url::Url;

use self::generic::{
    ChunkedBodyDecoder, FixedSizeBodyDecoder, HeaderField, MessageBodyDecoder,
    Request as GenericRequest, RequestBuilder as GenericRequestBuilder,
    Response as GenericResponse, ResponseHeader as GenericResponseHeader,
    ResponseHeaderDecoder as GenericResponseHeaderDecoder, SimpleBodyDecoder,
};

use crate::error::Error;

/// HTTP method.
#[allow(clippy::upper_case_acronyms)]
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
            Self::OPTIONS => "OPTIONS",
            Self::HEAD => "HEAD",
            Self::GET => "GET",
            Self::POST => "POST",
            Self::PUT => "PUT",
            Self::DELETE => "DELETE",
            Self::TRACE => "TRACE",
            Self::CONNECT => "CONNECT",
        }
    }
}

/// Valid URL schemes.
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Scheme {
    HTTP,
}

impl Scheme {
    /// Get default port for this URL scheme.
    fn default_port(self) -> u16 {
        match self {
            Self::HTTP => 80,
        }
    }
}

impl FromStr for Scheme {
    type Err = Error;

    fn from_str(method: &str) -> Result<Self, Error> {
        match &method.to_lowercase() as &str {
            "http" => Ok(Self::HTTP),
            _ => Err(Error::from_static_msg("invalid URL scheme")),
        }
    }
}

/// HTTP request.
#[derive(Clone)]
pub struct Request {
    host: String,
    port: u16,
    inner: GenericRequestBuilder,
    timeout: Option<Duration>,
    max_line_length: usize,
    max_header_lines: usize,
    ignore_response_body: bool,
}

impl Request {
    /// Create a new HTTP request.
    pub fn new(method: Method, url: &str, ignore_response_body: bool) -> Result<Self, Error> {
        let url = Url::from_str(url).map_err(|_| Error::from_static_msg("malformed URL"))?;

        let scheme = Scheme::from_str(url.scheme())?;

        let host = url.host();
        let port = url.port().unwrap_or_else(|| scheme.default_port());

        let mut path = url.path().to_string();

        if let Some(query) = url.query() {
            write!(path, "?{}", query).unwrap();
        }

        let app_version = env!("CARGO_PKG_VERSION");

        let uagent = format!("ArrowClient/{}", app_version);

        let inner = GenericRequestBuilder::new("HTTP", "1.0", method.name(), &path)
            .set_header_field(("Host", url.host()))
            .set_header_field(("User-Agent", uagent));

        let builder = Request {
            host: host.to_string(),
            port,
            inner,
            timeout: Some(Duration::from_secs(20)),
            max_line_length: 4096,
            max_header_lines: 1024,
            ignore_response_body,
        };

        Ok(builder)
    }

    /// Create a new GET request.
    pub fn get_header(url: &str) -> Result<Self, Error> {
        Self::new(Method::GET, url, true)
    }

    /// Set protocol version.
    pub fn set_version(mut self, version: &str) -> Self {
        self.inner = self.inner.set_version(version);
        self
    }

    /// Set a given header field.
    pub fn set_header_field<T>(mut self, field: T) -> Self
    where
        HeaderField: From<T>,
    {
        self.inner = self.inner.add_header_field(field);
        self
    }

    /// Set request timeout.
    pub fn set_request_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set maximum length of a single line accepted by the response parser.
    pub fn set_max_line_length(mut self, max_length: usize) -> Self {
        self.max_line_length = max_length;
        self
    }

    /// Set maximum number of header lines accepted by the response parser.
    pub fn set_max_header_lines(mut self, max_lines: usize) -> Self {
        self.max_header_lines = max_lines;
        self
    }

    /// Send the request and return a future response.
    async fn send_inner(self) -> Result<Response, Error> {
        let stream = TcpStream::connect((self.host.as_ref(), self.port)).await?;

        let codec = ClientCodec::new(
            self.max_line_length,
            self.max_header_lines,
            self.ignore_response_body,
        );

        let mut stream = codec.framed(stream);

        stream.send(self.inner.build()).await?;

        stream
            .next()
            .await
            .ok_or_else(|| Error::from_static_msg("server closed connection unexpectedly"))?
    }

    /// Send the request and return a future response.
    pub async fn send(self) -> Result<Response, Error> {
        if let Some(timeout) = self.timeout {
            tokio::time::timeout(timeout, self.send_inner())
                .await
                .map_err(|_| Error::from_static_msg("request timeout"))?
        } else {
            self.send_inner().await
        }
    }
}

/// HTTP response.
pub struct Response {
    inner: GenericResponse,
}

impl Response {
    /// Create a new HTTP response from a given generic response.
    fn new(response: GenericResponse) -> Result<Self, Error> {
        {
            let header = response.header();
            let protocol = header.protocol();
            let version = header.version();

            if protocol != "HTTP" {
                return Err(Error::from_static_msg("invalid protocol"));
            }

            if version != "1.0" && version != "1.1" {
                return Err(Error::from_static_msg("unsupported HTTP version"));
            }
        }

        let response = Self { inner: response };

        Ok(response)
    }

    /// Get protocol version.
    pub fn version(&self) -> &str {
        self.inner.header().version()
    }

    /// Get status code.
    pub fn status_code(&self) -> u16 {
        self.inner.header().status_code()
    }

    /// Get status line.
    pub fn status_line(&self) -> &str {
        self.inner.header().status_line()
    }

    /// Get response body.
    pub fn body(&self) -> &[u8] {
        self.inner.body()
    }

    /// Get header fields corresponding to a given name.
    pub fn get_header_fields(&self, name: &str) -> &[HeaderField] {
        self.inner.header().get_header_fields(name)
    }

    /// Get last header field of a given name.
    pub fn get_header_field(&self, name: &str) -> Option<&HeaderField> {
        self.inner.header().get_header_field(name)
    }

    /// Get value of the last header field with a given name.
    pub fn get_header_field_value(&self, name: &str) -> Option<&str> {
        self.inner.header().get_header_field_value(name)
    }
}

/// HTTP client codec.
pub struct ClientCodec {
    hdecoder: GenericResponseHeaderDecoder,
    bdecoder: Option<Box<dyn MessageBodyDecoder + Send>>,
    header: Option<GenericResponseHeader>,
    max_line_length: usize,
    ignore_response_body: bool,
}

impl ClientCodec {
    /// Create a new HTTP client codec.
    pub fn new(
        max_line_length: usize,
        max_header_lines: usize,
        ignore_response_body: bool,
    ) -> Self {
        let hdecoder = GenericResponseHeaderDecoder::new(max_line_length, max_header_lines);

        Self {
            hdecoder,
            bdecoder: None,
            header: None,
            max_line_length,
            ignore_response_body,
        }
    }
}

impl Decoder for ClientCodec {
    type Item = Response;
    type Error = Error;

    fn decode(&mut self, data: &mut BytesMut) -> Result<Option<Response>, Error> {
        if self.header.is_none()
            && let Some(header) = self.hdecoder.decode(data)?
        {
            let status_code = header.status_code();

            let bdecoder: Box<dyn MessageBodyDecoder + Send> =
                if (100..200).contains(&status_code) || status_code == 204 || status_code == 304 {
                    Box::new(FixedSizeBodyDecoder::new(0, self.ignore_response_body))
                } else if let Some(tenc) = header.get_header_field("transfer-encoding") {
                    let tenc = tenc.value().unwrap_or("").to_lowercase();

                    if tenc == "chunked" {
                        Box::new(ChunkedBodyDecoder::new(
                            self.max_line_length,
                            self.ignore_response_body,
                        ))
                    } else {
                        Box::new(SimpleBodyDecoder::new(self.ignore_response_body))
                    }
                } else if let Some(clength) = header.get_header_field("content-length") {
                    let clength = clength
                        .value()
                        .ok_or_else(|| Error::from_static_msg("missing Content-Length value"))?;
                    let clength = usize::from_str(clength)
                        .map_err(|_| Error::from_static_msg("unable to decode Content-Length"))?;

                    Box::new(FixedSizeBodyDecoder::new(
                        clength,
                        self.ignore_response_body,
                    ))
                } else {
                    Box::new(SimpleBodyDecoder::new(self.ignore_response_body))
                };

            self.bdecoder = Some(bdecoder);
            self.header = Some(header);
        }

        if let Some(mut bdecoder) = self.bdecoder.take() {
            if let Some(body) = bdecoder.decode(data)? {
                let header = self.header.take().expect("header is missing");

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
                let header = self.header.take().expect("header is missing");

                let response = GenericResponse::new(header, body);
                let response = Response::new(response)?;

                return Ok(Some(response));
            }

            self.bdecoder = Some(bdecoder);
        }

        Ok(None)
    }
}

impl Encoder<GenericRequest> for ClientCodec {
    type Error = io::Error;

    fn encode(&mut self, message: GenericRequest, buffer: &mut BytesMut) -> Result<(), io::Error> {
        let header = format!("{}", message.header());
        let body = message.body();

        buffer.extend_from_slice(header.as_bytes());
        buffer.extend_from_slice(body);

        Ok(())
    }
}
