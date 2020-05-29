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
use std::io;
use std::mem;

use std::collections::HashMap;
use std::error::Error as ErrorTrait;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::string::FromUtf8Error;

use bytes::{Buf, BytesMut};

use tokio_util::codec::Decoder;

use crate::utils::string::reader::Reader as StringReader;

/// Codec error.
#[derive(Debug, Clone)]
pub struct Error {
    msg: String,
}

impl Error {
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

impl ErrorTrait for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        f.write_str(&self.msg)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::new(format!("IO error: {}", err))
    }
}

impl From<FromUtf8Error> for Error {
    fn from(err: FromUtf8Error) -> Self {
        Self::new(format!("UTF-8 error: {}", err))
    }
}

/// HTTP-like Header field.
#[derive(Clone)]
pub struct HeaderField {
    nname: String,
    name: String,
    value: Option<String>,
}

impl HeaderField {
    /// Create a new HTTP-like header field.
    pub fn new<N, V>(name: N, value: Option<V>) -> Self
    where
        N: ToString,
        V: ToString,
    {
        let name = name.to_string();

        let value = match value {
            Some(v) => Some(v.to_string()),
            None => None,
        };

        Self {
            nname: name.to_lowercase(),
            name,
            value,
        }
    }

    /// Get name of the field.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get lowercase name of the field.
    pub fn lowercase_name(&self) -> &str {
        &self.nname
    }

    /// Get value of the field.
    pub fn value(&self) -> Option<&str> {
        match self.value.as_ref() {
            Some(v) => Some(v),
            None => None,
        }
    }
}

impl Display for HeaderField {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        f.write_str(&self.name)?;

        if let Some(ref value) = self.value {
            f.write_str(": ")?;
            f.write_str(value)?;
        }

        Ok(())
    }
}

impl<N> From<(N,)> for HeaderField
where
    N: ToString,
{
    fn from(tuple: (N,)) -> Self {
        let (name,) = tuple;

        Self::new(name, None as Option<String>)
    }
}

impl<N, V> From<(N, V)> for HeaderField
where
    N: ToString,
    V: ToString,
{
    fn from(tuple: (N, V)) -> Self {
        let (name, value) = tuple;

        Self::new(name, Some(value))
    }
}

impl FromStr for HeaderField {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let name;
        let value;

        if let Some(separator) = s.find(':') {
            let n = &s[..separator];
            let v = &s[separator + 1..];

            name = n.trim();
            value = Some(v.trim());
        } else {
            name = s.trim();
            value = None;
        }

        let field = Self::new(name, value);

        Ok(field)
    }
}

/// Collection of HTTP-like header fields.
#[derive(Clone, Default)]
pub struct HeaderFields {
    fields: Vec<HeaderField>,
    map: HashMap<String, Vec<HeaderField>>,
}

impl HeaderFields {
    /// Create a new collection of HTTP-like header fields.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a given header field into the collection.
    pub fn add(&mut self, field: HeaderField) {
        let name = field.lowercase_name().to_string();

        self.fields.push(field.clone());

        let mut fields = self
            .map
            .remove(&name)
            .unwrap_or_else(|| Vec::with_capacity(1));

        fields.push(field);

        self.map.insert(name, fields);
    }

    /// Replace the current list of header fields having the same name (if any)
    /// with the given one.
    pub fn set(&mut self, field: HeaderField) {
        let current_length = self.fields.len();

        let fields = mem::replace(&mut self.fields, Vec::with_capacity(current_length));

        let name = field.lowercase_name().to_string();

        for f in fields {
            if name != f.lowercase_name() {
                self.fields.push(f)
            }
        }

        self.fields.push(field.clone());

        let mut fields = Vec::with_capacity(1);

        fields.push(field);

        self.map.insert(name, fields);
    }

    /// Get header fields corresponding to a given name.
    pub fn get(&self, name: &str) -> &[HeaderField] {
        match self.map.get(&name.to_lowercase()) {
            Some(fields) => fields.as_ref(),
            None => &[],
        }
    }
}

impl<'a> IntoIterator for &'a HeaderFields {
    type Item = &'a HeaderField;
    type IntoIter = HeaderFieldsIter<'a>;

    fn into_iter(self) -> HeaderFieldsIter<'a> {
        HeaderFieldsIter::new(&self.fields)
    }
}

/// Iterator for the collection of header fields.
pub struct HeaderFieldsIter<'a> {
    inner: std::slice::Iter<'a, HeaderField>,
}

impl<'a> HeaderFieldsIter<'a> {
    fn new(fields: &'a [HeaderField]) -> HeaderFieldsIter<'a> {
        HeaderFieldsIter {
            inner: fields.iter(),
        }
    }
}

impl<'a> Iterator for HeaderFieldsIter<'a> {
    type Item = &'a HeaderField;

    fn next(&mut self) -> Option<&'a HeaderField> {
        self.inner.next()
    }
}

/// Type alias for HTTP-like request/response body.
pub type MessageBody = Box<[u8]>;

/// HTTP-like request header.
#[derive(Clone)]
pub struct RequestHeader {
    method: String,
    path: String,
    protocol: String,
    version: String,
    header_fields: HeaderFields,
}

impl RequestHeader {
    /// Create a new HTTP-like request header.
    fn new(protocol: &str, version: &str, method: &str, path: &str) -> Self {
        Self {
            method: method.to_string(),
            path: path.to_string(),
            protocol: protocol.to_string(),
            version: version.to_string(),
            header_fields: HeaderFields::new(),
        }
    }
}

impl Display for RequestHeader {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        f.write_str(&self.method)?;
        f.write_str(" ")?;
        f.write_str(&self.path)?;
        f.write_str(" ")?;
        f.write_str(&self.protocol)?;
        f.write_str("/")?;
        f.write_str(&self.version)?;
        f.write_str("\r\n")?;

        for field in &self.header_fields {
            // format the header field
            Display::fmt(field, f)?;

            f.write_str("\r\n")?;
        }

        f.write_str("\r\n")
    }
}

/// HTTP-like request.
#[derive(Clone)]
pub struct Request {
    header: RequestHeader,
    body: MessageBody,
}

impl Request {
    /// Create a new HTTP-like request.
    fn new(protocol: &str, version: &str, method: &str, path: &str) -> Self {
        Self {
            header: RequestHeader::new(protocol, version, method, path),
            body: Box::new([]),
        }
    }

    /// Get request header.
    pub fn header(&self) -> &RequestHeader {
        &self.header
    }

    /// Get request body.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// Request builder.
#[derive(Clone)]
pub struct RequestBuilder {
    request: Request,
}

impl RequestBuilder {
    /// Create a new request builder.
    pub fn new(protocol: &str, version: &str, method: &str, path: &str) -> Self {
        let request = Request::new(protocol, version, method, path);

        Self { request }
    }

    /// Set protocol version.
    pub fn set_version(mut self, version: &str) -> Self {
        self.request.header.version = version.to_string();
        self
    }

    /// Replace the current list of header fields having the same name (if any)
    /// with the given one.
    pub fn set_header_field<T>(mut self, field: T) -> Self
    where
        HeaderField: From<T>,
    {
        self.request
            .header
            .header_fields
            .set(HeaderField::from(field));
        self
    }

    /// Add a given header field.
    pub fn add_header_field<T>(mut self, field: T) -> Self
    where
        HeaderField: From<T>,
    {
        self.request
            .header
            .header_fields
            .add(HeaderField::from(field));
        self
    }

    /// Set request body.
    pub fn set_body<T>(mut self, body: T) -> Self
    where
        T: AsRef<[u8]>,
    {
        let body = body.as_ref().to_vec().into_boxed_slice();

        self.request.body = body;

        self
    }

    /// Build request.
    pub fn build(self) -> Request {
        self.request
    }
}

/// HTTP-like response header.
#[derive(Clone)]
pub struct ResponseHeader {
    protocol: String,
    version: String,
    status_code: u16,
    status_line: String,
    header_fields: HeaderFields,
}

impl ResponseHeader {
    /// Get protocol name.
    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    /// Get protocol version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Get status code.
    pub fn status_code(&self) -> u16 {
        self.status_code
    }

    /// Get status line.
    pub fn status_line(&self) -> &str {
        &self.status_line
    }

    /// Get header fields corresponding to a given name.
    pub fn get_header_fields(&self, name: &str) -> &[HeaderField] {
        self.header_fields.get(name)
    }

    /// Get last header field of a given name.
    pub fn get_header_field(&self, name: &str) -> Option<&HeaderField> {
        self.header_fields.get(name).last()
    }

    /// Get value of the last header field with a given name.
    pub fn get_header_field_value(&self, name: &str) -> Option<&str> {
        let value = self
            .header_fields
            .get(name)
            .last()
            .map(|field| field.value());

        match value {
            Some(Some(v)) => Some(v),
            Some(None) | None => None,
        }
    }
}

impl FromStr for ResponseHeader {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let mut reader = StringReader::new(s);

        let protocol = reader.read_until(|c| c == '/');

        reader
            .match_char('/')
            .map_err(|_| Error::new("invalid response header"))?;

        let version = reader.read_word();
        let status_code = reader.read_word();
        let status_line = reader.as_str();

        let status_code =
            u16::from_str(status_code).map_err(|_| Error::new("invalid response header"))?;

        let status_line = status_line.trim();

        let header = Self {
            protocol: protocol.to_string(),
            version: version.to_string(),
            status_code,
            status_line: status_line.to_string(),
            header_fields: HeaderFields::new(),
        };

        Ok(header)
    }
}

/// HTTP-like response.
#[derive(Clone)]
pub struct Response {
    header: ResponseHeader,
    body: MessageBody,
}

impl Response {
    /// Create a new HTTP-like response.
    pub fn new(header: ResponseHeader, body: MessageBody) -> Self {
        Self { header, body }
    }

    /// Get response header.
    pub fn header(&self) -> &ResponseHeader {
        &self.header
    }

    /// Get response body.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// Line decoder.
pub struct LineDecoder {
    separator: Box<[u8]>,
    buffer: Vec<u8>,
    max_length: usize,
}

impl LineDecoder {
    /// Create a new line decoder.
    pub fn new(separator: &[u8], max_length: usize) -> Self {
        let separator = separator.to_vec();

        Self {
            separator: separator.into_boxed_slice(),
            buffer: Vec::new(),
            max_length,
        }
    }

    /// Clear the internal line buffer.
    pub fn reset(&mut self) {
        self.buffer.clear();
    }
}

impl Decoder for LineDecoder {
    type Item = String;
    type Error = Error;

    fn decode(&mut self, data: &mut BytesMut) -> Result<Option<String>, Error> {
        let separator_length = self.separator.len();
        let old_buffer_length = self.buffer.len();

        let search_start = if old_buffer_length > separator_length {
            old_buffer_length - separator_length
        } else {
            0
        };

        // number of bytes to be appended
        let append = if (old_buffer_length + data.len()) > self.max_length {
            self.max_length - old_buffer_length
        } else {
            data.len()
        };

        // Copy data from the input buffer into the internal buffer but do not
        // remove it from the input buffer yet.
        self.buffer.extend_from_slice(&data[..append]);

        let new_buffer_length = self.buffer.len();

        let search_end = if new_buffer_length >= separator_length {
            new_buffer_length - separator_length + 1
        } else {
            0
        };

        for index in search_start..search_end {
            let line_length = index + separator_length;

            if &self.buffer[index..line_length] == self.separator.as_ref() {
                let line = self.buffer[..index].to_vec();

                let line = String::from_utf8(line)?;

                if line_length > old_buffer_length {
                    data.advance(line_length - old_buffer_length);
                }

                self.buffer.clear();

                return Ok(Some(line));
            }
        }

        data.advance(append);

        // no separator was found and the buffer is already full
        if new_buffer_length >= self.max_length {
            return Err(Error::new("input line is too long"));
        }

        Ok(None)
    }
}

/// Decoder for HTTP-like response headers.
pub struct ResponseHeaderDecoder {
    ldecoder: LineDecoder,
    header: Option<ResponseHeader>,
    field: String,
    lines: usize,
    max_lines: usize,
}

impl ResponseHeaderDecoder {
    /// Create a new decoder for HTTP-like response headers.
    pub fn new(max_line_length: usize, max_lines: usize) -> Self {
        Self {
            ldecoder: LineDecoder::new(b"\r\n", max_line_length),
            header: None,
            field: String::new(),
            lines: 0,
            max_lines,
        }
    }

    /// Reset the decoder and make it ready for parsing a new HTTP-like
    /// response header.
    pub fn reset(&mut self) {
        self.ldecoder.reset();
        self.field.clear();

        self.header = None;
        self.lines = 0;
    }
}

impl Decoder for ResponseHeaderDecoder {
    type Item = ResponseHeader;
    type Error = Error;

    fn decode(&mut self, data: &mut BytesMut) -> Result<Option<ResponseHeader>, Error> {
        while let Some(line) = self.ldecoder.decode(data)? {
            self.lines += 1;

            if self.lines > self.max_lines {
                return Err(Error::new("maximum number of lines exceeded"));
            }

            if let Some(mut header) = self.header.take() {
                // check if the current header field should be processed
                let commit_header_field = line.chars().next().map_or(true, |c| !c.is_whitespace());

                if commit_header_field && !self.field.is_empty() {
                    header.header_fields.add(self.field.parse()?);

                    self.field.clear();
                }

                self.field += &line;

                // reset the decoder and return the header
                if line.is_empty() {
                    self.reset();

                    return Ok(Some(header));
                }

                self.header = Some(header);
            } else {
                self.header = Some(line.parse()?);
            }
        }

        Ok(None)
    }
}

/// Common trait for HTTP-like message body decoders. This is just a helper
/// trait for creating trait objects from structs implementing the Decoder
/// trait where Item=MessageBody and Error=Error.
pub trait MessageBodyDecoder {
    /// Decode a given chunk of data.
    fn decode(&mut self, data: &mut BytesMut) -> Result<Option<MessageBody>, Error>;

    /// Process end of stream.
    fn decode_eof(&mut self, data: &mut BytesMut) -> Result<Option<MessageBody>, Error>;
}

impl<T> MessageBodyDecoder for T
where
    T: Decoder<Item = MessageBody, Error = Error>,
{
    fn decode(&mut self, data: &mut BytesMut) -> Result<Option<MessageBody>, Error> {
        Decoder::decode(self, data)
    }

    fn decode_eof(&mut self, data: &mut BytesMut) -> Result<Option<MessageBody>, Error> {
        Decoder::decode_eof(self, data)
    }
}

/// Simple HTTP-like message body decoder that consumes all data until EOF is
/// received.
pub struct SimpleBodyDecoder {
    body: Vec<u8>,
    ignore: bool,
}

impl SimpleBodyDecoder {
    /// Create a new simple body decoder.
    pub fn new(ignore_data: bool) -> Self {
        Self {
            body: Vec::new(),
            ignore: ignore_data,
        }
    }
}

impl Decoder for SimpleBodyDecoder {
    type Item = MessageBody;
    type Error = Error;

    fn decode(&mut self, data: &mut BytesMut) -> Result<Option<MessageBody>, Error> {
        let data = data.split();

        if !self.ignore {
            self.body.extend_from_slice(data.as_ref());
        }

        Ok(None)
    }

    fn decode_eof(&mut self, data: &mut BytesMut) -> Result<Option<MessageBody>, Error> {
        Decoder::decode(self, data)?;

        let body = mem::replace(&mut self.body, Vec::new());

        Ok(Some(body.into_boxed_slice()))
    }
}

/// HTTP-like message body decoder for fixed-size bodies. Note that it's
/// illegal to pass any more data to the decoder after a message body is
/// returned.
pub struct FixedSizeBodyDecoder {
    body: Option<Vec<u8>>,
    expected: usize,
    ignore: bool,
}

impl FixedSizeBodyDecoder {
    /// Create a new fixed-size decoder expecting a given number of bytes.
    pub fn new(expected: usize, ignore_data: bool) -> Self {
        let body = if ignore_data {
            Vec::new()
        } else {
            Vec::with_capacity(expected)
        };

        Self {
            body: Some(body),
            expected,
            ignore: ignore_data,
        }
    }
}

impl Decoder for FixedSizeBodyDecoder {
    type Item = MessageBody;
    type Error = Error;

    fn decode(&mut self, data: &mut BytesMut) -> Result<Option<MessageBody>, Error> {
        let take = if self.expected < data.len() {
            self.expected
        } else {
            data.len()
        };

        self.expected -= take;

        let data = data.split_to(take);

        if let Some(ref mut body) = self.body {
            if !self.ignore {
                body.extend_from_slice(data.as_ref());
            }
        }

        if self.expected > 0 {
            Ok(None)
        } else if let Some(body) = self.body.take() {
            Ok(Some(body.into_boxed_slice()))
        } else {
            Err(Error::new("no more data is expected"))
        }
    }

    fn decode_eof(&mut self, data: &mut BytesMut) -> Result<Option<MessageBody>, Error> {
        let res = Decoder::decode(self, data)?;

        if res.is_some() {
            Ok(res)
        } else if let Some(body) = self.body.take() {
            Ok(Some(body.into_boxed_slice()))
        } else {
            Err(Error::new("no more data is expected"))
        }
    }
}

/// Internal state of the chunked decoder.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum ChunkedDecoderState {
    ChunkHeader,
    ChunkBody,
    ChunkBodyDelimiter,
    TrailerPart,
    Completed,
}

/// Decoder for HTTP-like chunked bodies.
pub struct ChunkedBodyDecoder {
    state: ChunkedDecoderState,
    ldecoder: LineDecoder,
    body: Vec<u8>,
    expected: usize,
    ignore: bool,
}

impl ChunkedBodyDecoder {
    /// Create a new decoder for HTTP-like chunked bodies.
    pub fn new(max_line_length: usize, ignore_data: bool) -> Self {
        Self {
            state: ChunkedDecoderState::ChunkHeader,
            ldecoder: LineDecoder::new(b"\r\n", max_line_length),
            body: Vec::new(),
            expected: 0,
            ignore: ignore_data,
        }
    }

    /// Single decoding step.
    fn decoding_step(&mut self, data: &mut BytesMut) -> Result<Option<MessageBody>, Error> {
        match self.state {
            ChunkedDecoderState::ChunkHeader => self.decode_chunk_header(data),
            ChunkedDecoderState::ChunkBody => self.decode_chunk_body(data),
            ChunkedDecoderState::ChunkBodyDelimiter => self.decode_chunk_body_delimiter(data),
            ChunkedDecoderState::TrailerPart => self.decode_trailer_part(data),
            ChunkedDecoderState::Completed => Err(Error::new("no more data is expected")),
        }
    }

    /// Decode chunk header.
    fn decode_chunk_header(&mut self, data: &mut BytesMut) -> Result<Option<MessageBody>, Error> {
        if let Some(header) = self.ldecoder.decode(data)? {
            let mut reader = StringReader::new(&header);

            let size = reader.read_until(|c| c == ';');

            let size =
                usize::from_str_radix(size, 16).map_err(|_| Error::new("invalid chunk size"))?;

            self.expected = size;

            if size > 0 {
                self.state = ChunkedDecoderState::ChunkBody;
            } else {
                self.state = ChunkedDecoderState::TrailerPart;
            }
        }

        Ok(None)
    }

    /// Decode chunk body.
    fn decode_chunk_body(&mut self, data: &mut BytesMut) -> Result<Option<MessageBody>, Error> {
        let take = if self.expected < data.len() {
            self.expected
        } else {
            data.len()
        };

        self.expected -= take;

        let data = data.split_to(take);

        if !self.ignore {
            self.body.extend_from_slice(data.as_ref());
        }

        if self.expected == 0 {
            self.state = ChunkedDecoderState::ChunkBodyDelimiter;
        }

        Ok(None)
    }

    /// Decode chunk body delimiter (i.e. the new line between chunk body and
    /// and chunk header).
    fn decode_chunk_body_delimiter(
        &mut self,
        data: &mut BytesMut,
    ) -> Result<Option<MessageBody>, Error> {
        if self.ldecoder.decode(data)?.is_some() {
            self.state = ChunkedDecoderState::ChunkHeader;
        }

        Ok(None)
    }

    /// Decode trailer part and drop all its content.
    fn decode_trailer_part(&mut self, data: &mut BytesMut) -> Result<Option<MessageBody>, Error> {
        while let Some(line) = self.ldecoder.decode(data)? {
            if line.is_empty() {
                self.state = ChunkedDecoderState::Completed;

                // take the body without allocation
                let body = mem::replace(&mut self.body, Vec::new());

                return Ok(Some(body.into_boxed_slice()));
            }
        }

        Ok(None)
    }
}

impl Decoder for ChunkedBodyDecoder {
    type Item = MessageBody;
    type Error = Error;

    fn decode(&mut self, data: &mut BytesMut) -> Result<Option<MessageBody>, Error> {
        while !data.is_empty() {
            let res = self.decoding_step(data)?;

            if res.is_some() {
                return Ok(res);
            }
        }

        Ok(None)
    }

    fn decode_eof(&mut self, data: &mut BytesMut) -> Result<Option<MessageBody>, Error> {
        let res = Decoder::decode(self, data)?;

        if res.is_some() {
            Ok(res)
        } else if self.state == ChunkedDecoderState::Completed {
            Err(Error::new("no more data is expected"))
        } else {
            self.state = ChunkedDecoderState::Completed;

            // take the body without allocation
            let body = mem::replace(&mut self.body, Vec::new());

            Ok(Some(body.into_boxed_slice()))
        }
    }
}
