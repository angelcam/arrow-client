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

//! Common networking utils.

use std::io;
use std::ptr;

use std::io::{Read, Write, ErrorKind};
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

use mio::tcp::TcpStream;
use mio::{EventLoop, EventSet, Token, PollOpt, Handler};

use utils::RuntimeError;

use time;

/// Register a given TCP stream in a given event loop.
pub fn register_socket<H: Handler>(
    token: Token,
    stream: &TcpStream,
    readable: bool,
    writable: bool,
    event_loop: &mut EventLoop<H>) {
    let poll       = PollOpt::level();
    let mut events = EventSet::all();

    if !readable {
        events.remove(EventSet::readable());
    }

    if !writable {
        events.remove(EventSet::writable());
    }

    event_loop.register(stream, token, events, poll)
        .unwrap();
}

/// Re-register a given TCP stream in a given event loop.
pub fn reregister_socket<H: Handler>(
    token: Token,
    stream: &TcpStream,
    readable: bool,
    writable: bool,
    event_loop: &mut EventLoop<H>) {
    let poll       = PollOpt::level();
    let mut events = EventSet::all();

    if !readable {
        events.remove(EventSet::readable());
    }

    if !writable {
        events.remove(EventSet::writable());
    }

    event_loop.reregister(stream, token, events, poll)
        .unwrap();
}

/// Deregister a given socket.
pub fn deregister_socket<H: Handler>(
    stream: &TcpStream,
    event_loop: &mut EventLoop<H>) {
    event_loop.deregister(stream)
        .unwrap();
}

/// MIO TCP stream abstraction for ignoring EWOULDBLOCKs.
pub struct MioTcpStream {
    /// TCP stream.
    stream: TcpStream,
}

impl MioTcpStream {
    /// Connect to a given TCP socket address.
    pub fn connect(addr: &SocketAddr) -> io::Result<MioTcpStream> {
        let stream = try!(TcpStream::connect(addr));
        let res    = MioTcpStream {
            stream: stream
        };

        Ok(res)
    }

    /// Get reference to the underlaying TCP stream.
    pub fn get_ref(&self) -> &TcpStream {
        &self.stream
    }

    /// Take error from the underlaying TCP stream.
    pub fn get_error(&self) -> Option<io::Error> {
        match self.stream.take_socket_error() {
            Err(err) => Some(err),
            Ok(_)    => None
        }
    }
}

impl Read for MioTcpStream {
    /// Read data from the underlaying socket (EWOULDBLOCK is silently ignored).
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.stream.read(buf) {
            Err(ref err) if err.kind() == ErrorKind::WouldBlock => Ok(0),
            other => other
        }
    }
}

impl Write for MioTcpStream {
    /// Write data into the underlaying socket (EWOULDBLOCK is silently ignored).
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.stream.write(buf) {
            Err(ref err) if err.kind() == ErrorKind::WouldBlock => Ok(0),
            other => other
        }
    }

    /// Flush buffered data into the underlaying socket (EWOULDBLOCK is not ignored in this case).
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

/// Get socket address from a given argument.
pub fn get_socket_address<T>(s: T) -> Result<SocketAddr, RuntimeError>
    where T: ToSocketAddrs {
    s.to_socket_addrs()
        .ok()
        .ok_or(RuntimeError::from("unable get socket address"))?
        .next()
        .ok_or(RuntimeError::from("unable get socket address"))
}

/// Timeout provider for various network protocols.
#[derive(Debug)]
pub struct Timeout {
    timeout: Option<u64>,
}

impl Timeout {
    /// Create a new instance of Timeout. The initial state is reset.
    pub fn new() -> Timeout {
        Timeout {
            timeout: None
        }
    }

    /// Clear the timeout (i.e. the check() method will always return true
    /// until the timeout is set).
    pub fn clear(&mut self) -> &mut Self {
        self.timeout = None;
        self
    }

    /// Set the timeout.
    ///
    /// The timeout will expire after a specified delay in miliseconds.
    pub fn set(&mut self, delay_ms: u64) -> &mut Self {
        self.timeout = Some(time::precise_time_ns() + delay_ms * 1000000);
        self
    }

    /// Check if the timeout has already expired.
    ///
    /// The method returns false if the timeout has already expired, otherwise
    /// true is returned.
    pub fn check(&self) -> bool {
        match self.timeout {
            Some(t) => time::precise_time_ns() <= t,
            None    => true
        }
    }
}

/// Writer that can be used for buffering data.
pub struct WriteBuffer {
    buffer:   Vec<u8>,
    capacity: usize,
    offset:   usize,
    used:     usize,
}

impl WriteBuffer {
    /// Create a new buffer with a given capacity. Note that the capacity is
    /// only a soft limit. The buffer will always allow you to write more than
    /// its capacity.
    pub fn new(capacity: usize) -> WriteBuffer {
        let mut res = WriteBuffer {
            buffer:   Vec::with_capacity(capacity),
            capacity: capacity,
            offset:   0,
            used:     0
        };

        // TODO: replace this with resize (after it's stabilized)
        let buf_capacity = res.buffer.capacity();
        unsafe {
            res.buffer.set_len(buf_capacity);
        }

        res
    }

    /// Check if the buffer is full.
    pub fn is_full(&self) -> bool {
        self.used >= self.capacity
    }

    /// Check if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.used == 0
    }

    /// Get number of bytes available until the soft limit is reached.
    pub fn available(&self) -> usize {
        if self.is_full() {
            0
        } else {
            self.capacity - self.used
        }
    }

    /// Get number of buffered bytes.
    pub fn buffered(&self) -> usize {
        self.used
    }

    /// Get slice of bytes of the currently buffered data.
    pub fn as_bytes(&self) -> &[u8] {
        let start = self.offset;
        let end   = start + self.used;
        &self.buffer[start..end]
    }

    /// Drop a given number of bytes from the buffer.
    pub fn drop(&mut self, count: usize) {
        if count > self.used {
            self.offset += self.used;
            self.used    = 0;
        } else {
            self.offset += count;
            self.used   -= count;
        }
    }

    /// Drop all buffered data.
    pub fn clear(&mut self) {
        self.offset += self.used;
        self.used    = 0;
    }
}

impl Write for WriteBuffer {
    /// Write given data into the buffer.
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        // expand buffer if needed
        let buf_capacity = self.buffer.capacity();
        if (self.used + data.len()) > buf_capacity {
            // TODO: replace this with resize (after it's stabilized)
            self.buffer.reserve(self.used + data.len() - buf_capacity);
            let buf_capacity = self.buffer.capacity();
            unsafe {
                self.buffer.set_len(buf_capacity);
            }
        }

        // shift the buffered data to the left if needed
        let buf_capacity = self.buffer.capacity();
        if (self.offset + self.used + data.len()) > buf_capacity {
            let dst = self.buffer.as_mut_ptr();
            unsafe {
                let src = dst.offset(self.offset as isize);
                ptr::copy(src, dst, self.used);
            }
            self.offset = 0;
        }

        // write given data
        let offset     = self.offset + self.used;
        let mut buffer = &mut self.buffer[offset..];
        buffer.write_all(data)
            .unwrap();

        self.used += data.len();

        Ok(data.len())
    }

    /// Do nothing.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// IpAddr extension.
pub trait IpAddrEx {
    /// Get left-aligned byte representation of the IP address.
    fn bytes(&self) -> [u8; 16];

    /// Get IP address version.
    fn version(&self) -> u8;
}

impl IpAddrEx for IpAddr {
    fn bytes(&self) -> [u8; 16] {
        match self {
            &IpAddr::V4(ref ip_addr) => ip_addr.bytes(),
            &IpAddr::V6(ref ip_addr) => ip_addr.bytes()
        }
    }

    fn version(&self) -> u8 {
        match self {
            &IpAddr::V4(ref ip_addr) => ip_addr.version(),
            &IpAddr::V6(ref ip_addr) => ip_addr.version()
        }
    }
}

impl IpAddrEx for Ipv4Addr {
    fn bytes(&self) -> [u8; 16] {
        let octets  = self.octets();
        let mut res = [0u8; 16];

        for i in 0..octets.len() {
            res[i] = octets[i];
        }

        res
    }

    fn version(&self) -> u8 {
        4
    }
}

impl IpAddrEx for Ipv6Addr {
    fn bytes(&self) -> [u8; 16] {
        let segments = self.segments();
        let mut res  = [0u8; 16];

        for i in 0..segments.len() {
            let segment = segments[i];
            let j       = i << 1;
            res[j]      = (segment >> 8) as u8;
            res[j + 1]  = (segment & 0xff) as u8;
        }

        res
    }

    fn version(&self) -> u8 {
        6
    }
}
