// Copyright 2016 click2stream, Inc.
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

//! Custom SSL/TLS stream extension.

use std::io;

use std::net::SocketAddr;
use std::io::{Read, Write};

use mio;

use openssl::ssl;

use net::utils;

/// Process the handshake result.
macro_rules! handshake {
    ($t:expr) => {
        match $t {
            Ok(stream) => SslStreamState::Stream(stream),
            Err(err)   => match err {
                ssl::HandshakeError::Interrupted(hshake) => SslStreamState::Handshake(hshake),
                ssl::HandshakeError::Failure(err)        => SslStreamState::Error(err)
            }
        }
    };
}

/// The std::io::Error does not support clone so we need a little helper.
fn clone_io_error(err: &io::Error) -> io::Error {
    // XXX: this function is able to clone only OS errors
    match err.raw_os_error() {
        Some(code) => io::Error::from_raw_os_error(code),
        None       => io::Error::last_os_error()
    }
}

/// The openssl::ssl::Error enum does not support clone so we need a little helper.
fn clone_ssl_error(err: &ssl::Error) -> ssl::Error {
    match err {
        &ssl::Error::WantRead(ref err)  => ssl::Error::WantRead(clone_io_error(err)),
        &ssl::Error::WantWrite(ref err) => ssl::Error::WantWrite(clone_io_error(err)),
        &ssl::Error::Stream(ref err)    => ssl::Error::Stream(clone_io_error(err)),
        &ssl::Error::Ssl(ref err)       => ssl::Error::Ssl(err.clone()),
        &ssl::Error::WantX509Lookup     => ssl::Error::WantX509Lookup,
        &ssl::Error::ZeroReturn         => ssl::Error::ZeroReturn
    }
}

/// SSL/TLS state.
enum SslStreamState<S: Read + Write> {
    Handshake(ssl::MidHandshakeSslStream<S>),
    Stream(ssl::SslStream<S>),
    Error(ssl::Error),
}

impl<S: Read + Write> SslStreamState<S> {
    /// Get next state.
    fn next(self) -> Self {
        if let SslStreamState::Handshake(hshake) = self {
            handshake!(hshake.handshake())
        } else {
            self
        }
    }
}

/// Asynchronous SSL/TLS stream with automatic handshake handling.
pub struct SslStream<S: Read + Write> {
    state: Option<SslStreamState<S>>,
}

impl<S: Read + Write> SslStream<S> {
    /// Creates an SSL/TLS client operating over the provided stream.
    pub fn connect<T: ssl::IntoSsl>(into_ssl: T, stream: S) -> Result<Self, ssl::Error> {
        let state = handshake!(ssl::SslStream::connect(into_ssl, stream));

        if let SslStreamState::Error(err) = state {
            return Err(err);
        }

        let stream = SslStream {
            state: Some(state)
        };

        Ok(stream)
    }

    /// Read available data into a given buffer.
    pub fn ssl_read(&mut self, buf: &mut [u8]) -> Result<usize, ssl::Error> {
        self.get_ssl_stream()
            .and_then(|s| s.ssl_read(buf))
    }

    /// Write given data.
    pub fn ssl_write(&mut self, buf: &[u8]) -> Result<usize, ssl::Error> {
        self.get_ssl_stream()
            .and_then(|s| s.ssl_write(buf))
    }

    /// Get reference to the underlaying stream.
    pub fn get_ref(&self) -> Result<&S, ssl::Error> {
        match self.state {
            None => panic!("unknown SSL/TLS connection state"),
            Some(ref state) => match state {
                &SslStreamState::Stream(ref stream)    => Ok(stream.get_ref()),
                &SslStreamState::Handshake(ref hshake) => Ok(hshake.get_ref()),
                &SslStreamState::Error(ref err)        => Err(clone_ssl_error(err))
            }
        }
    }

    /// Get mutable reference to the underlaying stream.
    pub fn get_mut(&mut self) -> Result<&mut S, ssl::Error> {
        match self.state {
            None => panic!("unknown SSL/TLS connection state"),
            Some(ref mut state) => match state {
                &mut SslStreamState::Stream(ref mut stream)    => Ok(stream.get_mut()),
                &mut SslStreamState::Handshake(ref mut hshake) => Ok(hshake.get_mut()),
                &mut SslStreamState::Error(ref err)            => Err(clone_ssl_error(err))
            }
        }
    }

    /// Get the internal SSL stream (if available).
    fn get_ssl_stream(&mut self) -> Result<&mut ssl::SslStream<S>, ssl::Error> {
        match self.state.take() {
            None => panic!("unknown SSL/TLS connection state"),
            Some(state) => self.state = Some(state.next()),
        }

        match self.state {
            None => panic!("unknown SSL/TLS connection state"),
            Some(ref mut state) => match state {
                &mut SslStreamState::Stream(ref mut stream) => Ok(stream),
                &mut SslStreamState::Handshake(ref hshake)  => Err(clone_ssl_error(hshake.error())),
                &mut SslStreamState::Error(ref err)         => Err(clone_ssl_error(err))
            }
        }
    }
}

/// MIO SSL/TLS stream states.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum MioSslStreamState {
    Ok,
    ReaderWantRead,
    ReaderWantWrite,
    WriterWantRead,
    WriterWantWrite,
}

/// MIO SSL/TLS stream.
pub struct MioSslStream {
    stream: SslStream<mio::tcp::TcpStream>,
    state:  MioSslStreamState,
    token:  mio::Token,
}

impl MioSslStream {
    /// Create a new MIO SSL/TLS stream instance and register the underlaying socket within
    /// a given event loop.
    pub fn connect<S: ssl::IntoSsl, H: mio::Handler>(
        s: S,
        address: &SocketAddr,
        token: mio::Token,
        event_loop: &mut mio::EventLoop<H>) -> Result<Self, ssl::Error> {
        let tcp_stream = match mio::tcp::TcpStream::connect(address) {
            Err(err)   => return Err(ssl::Error::Stream(err)),
            Ok(stream) => stream
        };
        let ssl_stream = try!(SslStream::connect(s, tcp_stream));

        utils::register_socket(token, try!(ssl_stream.get_ref()),
            true, true, event_loop);

        let res = MioSslStream {
            stream: ssl_stream,
            state:  MioSslStreamState::Ok,
            token:  token
        };

        Ok(res)
    }

    /// Enable receiving readable and/or writable events for the underlaying TCP socket.
    pub fn enable_socket_events<H: mio::Handler>(
        &mut self,
        readable: bool,
        writable: bool,
        event_loop: &mut mio::EventLoop<H>) {
        if let Ok(stream) = self.stream.get_ref() {
            utils::reregister_socket(self.token, stream,
                readable, writable, event_loop);
        }
    }

    /// Read available data from the underlaying SSL/TLS socket into a given buffer.
    pub fn read<H: mio::Handler>(
        &mut self,
        buf: &mut [u8],
        event_loop: &mut mio::EventLoop<H>) -> Result<usize, ssl::Error> {
        match self.stream.ssl_read(buf) {
            Err(ssl::Error::WantRead(_)) => {
                self.state = MioSslStreamState::ReaderWantRead;
                self.enable_socket_events(true, false, event_loop);
                Ok(0)
            },
            Err(ssl::Error::WantWrite(_)) => {
                self.state = MioSslStreamState::ReaderWantWrite;
                self.enable_socket_events(false, true, event_loop);
                Ok(0)
            },
            other => {
                self.state = MioSslStreamState::Ok;
                self.enable_socket_events(true, true, event_loop);
                Ok(try!(other))
            }
        }
    }

    /// Write given data using the underlaying SSL/TLS socket.
    pub fn write<H: mio::Handler>(
        &mut self,
        data: &[u8],
        event_loop: &mut mio::EventLoop<H>) -> Result<usize, ssl::Error> {
        match self.stream.ssl_write(data) {
            Err(ssl::Error::WantRead(_)) => {
                self.state = MioSslStreamState::WriterWantRead;
                self.enable_socket_events(true, false, event_loop);
                Ok(0)
            },
            Err(ssl::Error::WantWrite(_)) => {
                self.state = MioSslStreamState::WriterWantWrite;
                self.enable_socket_events(false, true, event_loop);
                Ok(0)
            },
            other => {
                self.state = MioSslStreamState::Ok;
                self.enable_socket_events(true, true, event_loop);
                Ok(try!(other))
            }
        }
    }

    /// Check if the underlaying socket is ready to read.
    pub fn can_read(&self, event_set: mio::EventSet) -> bool {
        match self.state {
            MioSslStreamState::Ok              => event_set.is_readable(),
            MioSslStreamState::ReaderWantRead  => event_set.is_readable(),
            MioSslStreamState::ReaderWantWrite => event_set.is_writable(),
            _ => false
        }
    }

    /// Check if the underlaying socket is ready to write.
    pub fn can_write(&self, event_set: mio::EventSet) -> bool {
        match self.state {
            MioSslStreamState::Ok              => event_set.is_writable(),
            MioSslStreamState::WriterWantRead  => event_set.is_readable(),
            MioSslStreamState::WriterWantWrite => event_set.is_writable(),
            _ => false
        }
    }

    /// Take error (if any).
    pub fn get_error(&self) -> Option<ssl::Error> {
        match self.stream.get_ref() {
            Err(err)   => Some(err),
            Ok(stream) => match stream.take_socket_error() {
                Err(err) => Some(ssl::Error::Stream(err)),
                Ok(_)    => None
            }
        }
    }
}
