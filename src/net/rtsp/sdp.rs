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

//! SDP definitions.

use std::{
    fmt::{self, Display, Formatter},
    num::ParseIntError,
    str::FromStr,
};

use str_reader::StringReader;

/// SDP parsing error.
#[derive(Debug, Clone)]
pub struct ParseError {
    msg: String,
}

impl ParseError {
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

impl std::error::Error for ParseError {}

impl Display for ParseError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str(&self.msg)
    }
}

impl From<str_reader::ParseError> for ParseError {
    fn from(err: str_reader::ParseError) -> Self {
        Self::new(err.to_string())
    }
}

impl From<ParseIntError> for ParseError {
    fn from(err: ParseIntError) -> Self {
        Self::new(err.to_string())
    }
}

/// SDP parsing result.
pub type Result<T> = std::result::Result<T, ParseError>;

/// Session Description.
///
/// The implementation is incomplete as we need only a small subset of SDP
/// features. The parser accepts also some invalid session descriptions in
/// order to support as many faulty RTSP servers as possible.
#[derive(Debug, Clone)]
pub struct SessionDescription {
    /// SDP version.
    pub version: i32,
    /// Media descriptions.
    pub media_descriptions: Vec<MediaDescription>,
    // XXX: we ignore everything else as wo do not need it
}

impl SessionDescription {
    /// Create a new session description.
    fn new() -> Self {
        Self {
            version: 0,
            media_descriptions: Vec::new(),
        }
    }

    /// Parse session description from a given string.
    pub fn parse(sdp: &[u8]) -> Result<Self> {
        SessionDescriptionParser::parse(sdp)
    }
}

/// SDP media type.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MediaType {
    Audio,
    Video,
    Text,
    Application,
    Message,
    Other(String),
}

impl<'a> From<&'a str> for MediaType {
    fn from(s: &'a str) -> Self {
        match &s.to_lowercase() as &str {
            "audio" => Self::Audio,
            "video" => Self::Video,
            "text" => Self::Text,
            "application" => Self::Application,
            "message" => Self::Message,
            _ => Self::Other(s.to_string()),
        }
    }
}

/// SDP media description.
#[derive(Debug, Clone)]
pub struct MediaDescription {
    /// Media type.
    pub media_type: MediaType,
    /// Port.
    pub port: u16,
    /// Number of ports.
    pub nb_ports: Option<u16>,
    /// Protocol.
    pub protocol: String,
    /// Formats.
    pub formats: Vec<String>,
    /// Attributes.
    pub attributes: Vec<Attribute>,
    // XXX: we ignore the i, c, b and k lines as we don't need them
}

impl FromStr for MediaDescription {
    type Err = ParseError;

    fn from_str(val: &str) -> std::result::Result<Self, Self::Err> {
        let mut reader = StringReader::new(val.trim());

        let mtype = reader.read_word();

        reader.skip_whitespace();

        let port = reader.read_until(|c| !c.is_ascii_digit()).parse()?;

        reader.skip_whitespace();

        let c = reader
            .current_char()
            .ok_or_else(|| ParseError::new("empty input"))?;

        let np = if c == '/' {
            reader.skip_char();
            reader.skip_whitespace();

            let val = reader.read_until(|c| !c.is_ascii_digit()).parse()?;

            Some(val)
        } else {
            None
        };

        let protocol = reader.read_word();

        let mut formats = Vec::new();

        while !reader.is_empty() {
            let format = reader.read_word().to_string();

            formats.push(format);
        }

        let res = Self {
            media_type: MediaType::from(mtype),
            port,
            nb_ports: np,
            protocol: protocol.to_string(),
            formats,
            attributes: Vec::new(),
        };

        Ok(res)
    }
}

/// Session or media attribute.
#[derive(Debug, Clone)]
pub struct Attribute {
    /// Attribute name.
    pub name: String,
    /// Attribute value.
    pub value: Option<String>,
}

impl Attribute {
    /// Create a new attribute.
    pub fn new(name: &str, value: Option<&str>) -> Self {
        Self {
            name: name.to_string(),
            value: value.map(|v| v.to_string()),
        }
    }
}

impl FromStr for Attribute {
    type Err = ParseError;

    fn from_str(val: &str) -> Result<Self> {
        let mut val = val.splitn(2, ':');

        if let Some(name) = val.next() {
            let name = name.trim();
            let value = val.next().map(|v| v.trim());

            Ok(Self::new(name, value))
        } else {
            Err(ParseError::new("invalid attribute"))
        }
    }
}

/// Common trait for types that can be parsed from a given attribute.
pub trait FromAttribute: Sized {
    type Err;

    fn from_attr(attr: &Attribute) -> std::result::Result<Self, Self::Err>;
}

/// Representation of the "rtpmap" attribute.
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone)]
pub struct RTPMap {
    /// Payload type (corresponding to one of the media formats).
    pub payload_type: u32,
    /// Payload encoding.
    pub encoding: String,
    /// Clock rate.
    pub clock_rate: u32,
    /// Encoding parameters.
    pub encoding_params: Option<String>,
}

impl FromStr for RTPMap {
    type Err = ParseError;

    fn from_str(val: &str) -> std::result::Result<Self, Self::Err> {
        let mut reader = StringReader::new(val.trim());

        let pt = reader.read_until(|c| !c.is_ascii_digit()).parse()?;

        let enc = reader.read_until(|c| c == '/').trim().to_string();

        reader.match_char('/')?;
        reader.skip_whitespace();

        let cr = reader.read_until(|c| !c.is_ascii_digit()).parse()?;

        reader.skip_whitespace();

        let eps = if reader.is_empty() {
            None
        } else {
            reader.match_char('/')?;
            reader.skip_whitespace();

            let params = reader.as_str().to_string();

            Some(params)
        };

        let res = Self {
            payload_type: pt,
            encoding: enc,
            clock_rate: cr,
            encoding_params: eps,
        };

        Ok(res)
    }
}

impl FromAttribute for RTPMap {
    type Err = ParseError;

    fn from_attr(attr: &Attribute) -> std::result::Result<Self, Self::Err> {
        let key = attr.name.to_lowercase();

        if key == "rtpmap" {
            if let Some(ref val) = attr.value {
                Self::from_str(val).map_err(|_| ParseError::new("invalid attribute"))
            } else {
                Err(ParseError::new("invalid attribute"))
            }
        } else {
            Err(ParseError::new("invalid attribute"))
        }
    }
}

/// Incremental line reader. It takes both CR and LF as line separators.
struct LineReader {
    buffer: Vec<u8>,
    capacity: usize,
    complete: bool,
    partial: bool,
}

impl LineReader {
    /// Create a new line reader with a given line length limit.
    fn new(limit: usize) -> Self {
        Self {
            buffer: Vec::new(),
            capacity: limit,
            complete: false,
            partial: false,
        }
    }

    /// Get current line.
    fn line(&self) -> Option<&[u8]> {
        if self.partial {
            Some(&self.buffer)
        } else {
            None
        }
    }

    /// Check if the current line is complete.
    fn is_complete(&self) -> bool {
        self.complete
    }

    /// Clear the current line.
    fn clear(&mut self) {
        self.buffer.clear();

        self.complete = false;
        self.partial = false;
    }

    /// Append given data and return number of consumed bytes or error in case
    /// the line length has been exceeded.
    fn append(&mut self, data: &[u8]) -> Result<usize> {
        let mut pos = 0;

        while !self.complete && pos < data.len() {
            self.partial = true;

            if self.buffer.len() >= self.capacity {
                return Err(ParseError::new("line length exceeded"));
            } else if data[pos] == 0x0d || data[pos] == 0x0a {
                self.complete = true;
            } else {
                self.buffer.push(data[pos]);
            }

            pos += 1;
        }

        Ok(pos)
    }
}

/// Line iterator (it uses the line reader).
struct LineIterator<'a> {
    reader: LineReader,
    content: &'a [u8],
    offset: usize,
}

impl<'a> LineIterator<'a> {
    /// Create a new line iterator for a given reader and content.
    fn new(reader: LineReader, content: &'a [u8]) -> Self {
        Self {
            reader,
            content,
            offset: 0,
        }
    }

    /// Return next line or None if there are no more lines. An error is
    /// returned if the line length has been exceeded.
    fn next(&mut self) -> Result<Option<Vec<u8>>> {
        self.reader.clear();

        let content = self.content;
        let mut offset = self.offset;

        while !self.reader.is_complete() && offset < content.len() {
            offset += self.reader.append(&content[offset..])?;
        }

        self.offset = offset;

        let line = self.reader.line().map(|slice| slice.to_vec());

        Ok(line)
    }
}

/// Session description parser.
struct SessionDescriptionParser {
    sdp: SessionDescription,
}

impl SessionDescriptionParser {
    /// Parse session description from a given string.
    fn parse(sdp: &[u8]) -> Result<SessionDescription> {
        let mut parser = Self {
            sdp: SessionDescription::new(),
        };

        let reader = LineReader::new(4096);
        let mut lines = LineIterator::new(reader, sdp);

        parser.process_lines(&mut lines)?;

        Ok(parser.sdp)
    }

    /// Process SDP lines.
    fn process_lines(&mut self, lines: &mut LineIterator<'_>) -> Result<()> {
        while let Some(line) = lines.next()? {
            self.process_line(&line, lines)?;
        }

        Ok(())
    }

    /// Process a given SDP line.
    fn process_line(&mut self, line: &[u8], lines: &mut LineIterator<'_>) -> Result<()> {
        if let Some(first) = trim_left(line).first() {
            match *first as char {
                'v' => self.process_version(line),
                't' => self.process_time_description(line, lines),
                'm' => self.process_media_description(line, lines),
                _ => Ok(()), // ignore unknown line types
            }
        } else {
            Ok(())
        }
    }

    /// Process SDP "v" line.
    fn process_version(&mut self, line: &[u8]) -> Result<()> {
        let line = String::from_utf8_lossy(line);

        let mut reader = StringReader::new(line.as_ref());

        reader.skip_whitespace();
        reader
            .match_char('v')
            .map_err(|_| ParseError::new("invalid version line"))?;
        reader.skip_whitespace();
        reader
            .match_char('=')
            .map_err(|_| ParseError::new("invalid version line"))?;

        let val = reader
            .read_u32()
            .map_err(|_| ParseError::new("invalid version line"))?;

        self.sdp.version = val as i32;

        Ok(())
    }

    /// Process SDP time description.
    fn process_time_description(&mut self, _: &[u8], lines: &mut LineIterator<'_>) -> Result<()> {
        while let Some(ref line) = lines.next()? {
            if let Some(first) = trim_left(line).first() {
                match *first as char {
                    'r' => (),
                    _ => self.process_line(line, lines)?,
                }
            }
        }

        Ok(())
    }

    /// Process SDP media description.
    fn process_media_description(
        &mut self,
        line: &[u8],
        lines: &mut LineIterator<'_>,
    ) -> Result<()> {
        let line = String::from_utf8_lossy(line);

        let mut reader = StringReader::new(line.as_ref());

        reader.skip_whitespace();
        reader
            .match_char('m')
            .map_err(|_| ParseError::new("invalid media description line"))?;
        reader.skip_whitespace();
        reader
            .match_char('=')
            .map_err(|_| ParseError::new("invalid media description line"))?;
        reader.skip_whitespace();

        let md = MediaDescription::from_str(reader.as_str())
            .map_err(|_| ParseError::new("invalid media description line"))?;

        self.sdp.media_descriptions.push(md);

        while let Some(ref line) = lines.next()? {
            if let Some(first) = trim_left(line).first() {
                match *first as char {
                    'i' | 'c' | 'b' | 'k' => (),
                    'a' => self.process_media_attribute(line)?,
                    _ => self.process_line(line, lines)?,
                }
            }
        }

        Ok(())
    }

    /// Process SDP media attribute.
    fn process_media_attribute(&mut self, line: &[u8]) -> Result<()> {
        let line = String::from_utf8_lossy(line);

        let mut reader = StringReader::new(line.as_ref());

        reader.skip_whitespace();
        reader
            .match_char('a')
            .map_err(|_| ParseError::new("invalid media attribute line"))?;
        reader.skip_whitespace();
        reader
            .match_char('=')
            .map_err(|_| ParseError::new("invalid media attribute line"))?;
        reader.skip_whitespace();

        let attr = Attribute::from_str(reader.as_str())
            .map_err(|_| ParseError::new("invalid media attribute line"))?;

        let last_md = self.sdp.media_descriptions.last_mut().unwrap();

        last_md.attributes.push(attr);

        Ok(())
    }
}

fn trim_left(buffer: &[u8]) -> &[u8] {
    for i in 0..buffer.len() {
        let c = buffer[i] as char;
        if !c.is_whitespace() {
            return &buffer[i..];
        }
    }

    &[]
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parsing_valid() {
        let sdp = "v=0\r\n".to_string()
            + "o=alice 2890844526 2890844527 IN IP4 host.atlanta.example.com\r"
            + "s=\n"
            + "c=IN IP4 host.atlanta.example.com\n"
            + "t=0 0\n"
            + "m=audio 51372 RTP/AVP 0\n"
            + "a=rtpmap:0 PCMU/8000\n"
            + "m=audio 51378 RTP/AVP 0\n"
            + "a=rtpmap:0 PCMU/8000/2\n"
            + "m=video 51374 RTP/AVP 31\n"
            + "a=rtpmap:31 H261/90000\n"
            + "m=video 51376/2 RTP/AVP 96\n"
            + "a=rtpmap:96 H264/90000\n"
            + "a=recvonly";

        let sdp = SessionDescription::parse(sdp.as_bytes()).unwrap();

        assert_eq!(sdp.version, 0);
        assert_eq!(sdp.media_descriptions.len(), 4);

        let md1 = &sdp.media_descriptions[0];

        assert_eq!(md1.media_type, MediaType::Audio);
        assert_eq!(md1.port, 51372);
        assert_eq!(md1.nb_ports, None);
        assert_eq!(&md1.protocol, "RTP/AVP");
        assert_eq!(&md1.formats as &[String], &["0"]);
        assert_eq!(md1.attributes.len(), 1);

        let attr = RTPMap::from_attr(&md1.attributes[0]).unwrap();

        assert_eq!(attr.payload_type, 0);
        assert_eq!(&attr.encoding, "PCMU");
        assert_eq!(attr.clock_rate, 8000);

        let md2 = &sdp.media_descriptions[1];
        let attr = RTPMap::from_attr(&md2.attributes[0]).unwrap();

        assert_eq!(&attr.encoding_params, &Some("2".to_string()));

        let md3 = &sdp.media_descriptions[3];

        assert_eq!(md3.media_type, MediaType::Video);
        assert_eq!(md3.port, 51376);
        assert_eq!(md3.nb_ports, Some(2));
        assert_eq!(&md3.protocol, "RTP/AVP");
        assert_eq!(&md3.formats as &[String], &["96"]);
        assert_eq!(md3.attributes.len(), 2);

        let attr = RTPMap::from_attr(&md3.attributes[0]).unwrap();

        assert_eq!(attr.payload_type, 96);
        assert_eq!(&attr.encoding, "H264");
        assert_eq!(attr.clock_rate, 90000);

        let attr = &md3.attributes[1];

        assert_eq!(&attr.name, "recvonly");
        assert_eq!(attr.value, None);
    }

    #[test]
    fn test_parsing_faulty() {
        let sdp = " v = 5 \r\n".to_string()
            + " m\t=\taudio 51372 / 9 RTP/AVP 0 1   2 \t3 \n\n\n"
            + " a = RTPmap : 96 H264 / 90000 / 7 \n";

        let sdp = SessionDescription::parse(sdp.as_bytes()).unwrap();

        assert_eq!(sdp.version, 5);
        assert_eq!(sdp.media_descriptions.len(), 1);

        let md = &sdp.media_descriptions[0];

        assert_eq!(md.media_type, MediaType::Audio);
        assert_eq!(md.port, 51372);
        assert_eq!(md.nb_ports, Some(9));
        assert_eq!(&md.protocol, "RTP/AVP");
        assert_eq!(&md.formats as &[String], &["0", "1", "2", "3"]);
        assert_eq!(md.attributes.len(), 1);

        let attr = RTPMap::from_attr(&md.attributes[0]).unwrap();

        assert_eq!(attr.payload_type, 96);
        assert_eq!(&attr.encoding, "H264");
        assert_eq!(attr.clock_rate, 90000);
        assert_eq!(attr.encoding_params, Some("7".to_string()));
    }

    #[test]
    fn test_parsing_invalid() {
        let sdp = " v = foo \r\n".to_string()
            + " m\t=\taudio 51372 / 9 RTP/AVP 0 1   2 \t3 \n\n\n"
            + " a = RTPmap : 96 H264 / 90000 / 7 \n";

        let sdp = SessionDescription::parse(sdp.as_bytes());

        assert!(sdp.is_err());

        let sdp = " v = 5 \r\n".to_string()
            + " m\t=\taudio foo / 9 RTP/AVP 0 1   2 \t3 \n\n\n"
            + " a = RTPmap : 96 H264 / 90000 / 7 \n";

        let sdp = SessionDescription::parse(sdp.as_bytes());

        assert!(sdp.is_err());

        let attr = RTPMap::from_attr(&Attribute::new("rtpsmap", Some("9 H264/9")));

        assert!(attr.is_err());

        let attr = RTPMap::from_attr(&Attribute::new("rtpmap", Some("f H264/9")));

        assert!(attr.is_err());

        let attr = RTPMap::from_attr(&Attribute::new("rtpmap", Some("0 H264/f")));

        assert!(attr.is_err());

        let attr = RTPMap::from_attr(&Attribute::new("rtpmap", Some("0 H/9\\x")));

        assert!(attr.is_err());
    }
}
