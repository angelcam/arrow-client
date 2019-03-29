// Copyright 2018 click2stream, Inc.
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

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io::{Read, Write};

use futures::{Async, Future, Poll};

use openssl::error::ErrorStack as SslErrorStack;
use openssl::ssl::Error as SslError;
use openssl::ssl::{HandshakeError, SslConnector, SslStream};

use tokio::io::{AsyncRead, AsyncWrite};

/// TLS error.
#[derive(Debug, Clone)]
pub struct TlsError {
    msg: String,
}

impl Error for TlsError {
    fn description(&self) -> &str {
        &self.msg
    }
}

impl Display for TlsError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        f.write_str(&self.msg)
    }
}

impl From<String> for TlsError {
    fn from(s: String) -> TlsError {
        TlsError { msg: s }
    }
}

impl<'a> From<&'a str> for TlsError {
    fn from(s: &'a str) -> TlsError {
        TlsError::from(s.to_string())
    }
}

impl From<SslError> for TlsError {
    fn from(err: SslError) -> TlsError {
        TlsError::from(format!("{}", err))
    }
}

impl From<SslErrorStack> for TlsError {
    fn from(err: SslErrorStack) -> TlsError {
        TlsError::from(format!("{}", err))
    }
}

/// Asynchronous TLS stream.
pub struct TlsStream<S> {
    inner: SslStream<S>,
}

impl<S> Read for TlsStream<S>
where
    S: Read + Write,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<S> Write for TlsStream<S>
where
    S: Read + Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<S> AsyncRead for TlsStream<S> where S: AsyncRead + AsyncWrite {}

impl<S> AsyncWrite for TlsStream<S>
where
    S: AsyncRead + AsyncWrite,
{
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        if let Err(err) = self.inner.shutdown() {
            match err.into_io_error() {
                Ok(err) => {
                    if err.kind() == io::ErrorKind::WouldBlock {
                        return Ok(Async::NotReady);
                    } else {
                        return Err(err);
                    }
                }
                Err(err) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("TLS shutdown error: {}", err),
                    ));
                }
            }
        }

        self.inner.get_mut().shutdown()
    }
}

impl<S> From<SslStream<S>> for TlsStream<S> {
    fn from(stream: SslStream<S>) -> TlsStream<S> {
        TlsStream { inner: stream }
    }
}

/// A pending TLS connection.
pub struct TlsConnect<S> {
    handshake: Option<Result<SslStream<S>, HandshakeError<S>>>,
}

impl<S> Future for TlsConnect<S>
where
    S: AsyncRead + AsyncWrite,
{
    type Item = TlsStream<S>;
    type Error = TlsError;

    fn poll(&mut self) -> Poll<TlsStream<S>, TlsError> {
        match self
            .handshake
            .take()
            .expect("the future has been already resolved")
        {
            Ok(stream) => Ok(Async::Ready(stream.into())),
            Err(HandshakeError::SetupFailure(err)) => Err(TlsError::from(err)),
            Err(HandshakeError::Failure(m)) => Err(TlsError::from(m.into_error())),
            Err(HandshakeError::WouldBlock(m)) => match m.handshake() {
                Ok(stream) => Ok(Async::Ready(stream.into())),
                Err(HandshakeError::SetupFailure(err)) => Err(TlsError::from(err)),
                Err(HandshakeError::Failure(m)) => Err(TlsError::from(m.into_error())),
                Err(HandshakeError::WouldBlock(m)) => {
                    self.handshake = Some(Err(HandshakeError::WouldBlock(m)));

                    Ok(Async::NotReady)
                }
            },
        }
    }
}

/// Asynchronous TLS connector.
#[derive(Clone)]
pub struct TlsConnector {
    inner: SslConnector,
}

impl TlsConnector {
    /// Take a given asynchronous stream and perform a TLS handshake.
    pub fn connect_async<S>(&self, stream: S) -> TlsConnect<S>
    where
        S: AsyncRead + AsyncWrite,
    {
        // NOTE: We do not need to validate the server name because we use only one root
        // certificate. It's a self signed certificate issued directly by Angelcam and used
        // only for Arrow.
        let handshake = self
            .inner
            .configure()
            .map_err(|err| HandshakeError::from(err))
            .and_then(move |configuration| {
                configuration
                    .verify_hostname(false)
                    .connect("hostname", stream)
            });

        TlsConnect {
            handshake: Some(handshake),
        }
    }
}

impl From<SslConnector> for TlsConnector {
    fn from(connector: SslConnector) -> TlsConnector {
        TlsConnector { inner: connector }
    }
}
