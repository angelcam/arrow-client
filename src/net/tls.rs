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

use std::cell::RefCell;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io::{Read, Write};
use std::pin::Pin;

use futures::future::Future;
use futures::task::{Context, Poll, Waker};

use openssl::error::ErrorStack as SslErrorStack;
use openssl::ssl::Error as SslError;
use openssl::ssl::{HandshakeError, SslConnector, SslStream};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, ToSocketAddrs};

/// TLS error.
#[derive(Debug, Clone)]
pub struct TlsError {
    msg: String,
}

impl TlsError {
    /// Create a new error with a given message.
    pub fn new<T>(msg: T) -> Self
    where
        T: ToString,
    {
        Self {
            msg: msg.to_string(),
        }
    }
}

impl Error for TlsError {}

impl Display for TlsError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        f.write_str(&self.msg)
    }
}

impl From<io::Error> for TlsError {
    fn from(err: io::Error) -> Self {
        Self::new(err)
    }
}

impl From<SslError> for TlsError {
    fn from(err: SslError) -> Self {
        Self::new(err)
    }
}

impl From<SslErrorStack> for TlsError {
    fn from(err: SslErrorStack) -> Self {
        Self::new(err)
    }
}

thread_local! {
    /// An async context set when entering an async function to be later used
    /// by the IO methods within the `InnerSslStream`.
    static ASYNC_CONTEXT: RefCell<Option<Waker>> = RefCell::new(None);
}

/// A struct that will remove the async context when dropped.
struct DropAsyncContext;

impl Drop for DropAsyncContext {
    fn drop(&mut self) {
        ASYNC_CONTEXT.with(|v| {
            *v.borrow_mut() = None;
        })
    }
}

/// Set the async context.
fn set_async_context(cx: &Context) -> DropAsyncContext {
    ASYNC_CONTEXT.with(|v| {
        *v.borrow_mut() = Some(cx.waker().clone());
    });

    DropAsyncContext
}

/// Get the stored async context.
fn with_async_context<F, R>(f: F) -> R
where
    F: FnOnce(&mut Context) -> R,
{
    ASYNC_CONTEXT.with(|v| {
        let cell = v.borrow();
        let waker = cell.as_ref().expect("no async context set");

        let mut context = Context::from_waker(waker);

        f(&mut context)
    })
}

/// Helper struct.
struct InnerSslStream<S> {
    inner: S,
}

impl<S> InnerSslStream<S> {
    /// Create a new inner stream.
    fn new(stream: S) -> Self {
        Self { inner: stream }
    }
}

impl<S> Read for InnerSslStream<S>
where
    S: AsyncRead + Unpin,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        with_async_context(|cx| {
            let inner = Pin::new(&mut self.inner);

            if let Poll::Ready(res) = inner.poll_read(cx, buf) {
                res
            } else {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
        })
    }
}

impl<S> Write for InnerSslStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        with_async_context(|cx| {
            let inner = Pin::new(&mut self.inner);

            if let Poll::Ready(res) = inner.poll_write(cx, buf) {
                res
            } else {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
        })
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        with_async_context(|cx| {
            let inner = Pin::new(&mut self.inner);

            if let Poll::Ready(res) = inner.poll_flush(cx) {
                res
            } else {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
        })
    }
}

/// Asynchronous TLS stream.
pub struct TlsStream<S> {
    inner: SslStream<InnerSslStream<S>>,
}

impl<S> AsyncRead for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<Result<usize, io::Error>> {
        let _drop_context = set_async_context(cx);

        match self.inner.read(buf) {
            Ok(len) => Poll::Ready(Ok(len)),
            Err(err) => match err.kind() {
                io::ErrorKind::WouldBlock => Poll::Pending,
                _ => Poll::Ready(Err(err)),
            },
        }
    }
}

impl<S> AsyncWrite for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let _drop_context = set_async_context(cx);

        match self.inner.write(buf) {
            Ok(len) => Poll::Ready(Ok(len)),
            Err(err) => match err.kind() {
                io::ErrorKind::WouldBlock => Poll::Pending,
                _ => Poll::Ready(Err(err)),
            },
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        let _drop_context = set_async_context(cx);

        match self.inner.flush() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(err) => match err.kind() {
                io::ErrorKind::WouldBlock => Poll::Pending,
                _ => Poll::Ready(Err(err)),
            },
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        let _drop_context = set_async_context(cx);

        if let Err(err) = self.inner.shutdown() {
            match err.into_io_error() {
                Ok(err) => match err.kind() {
                    io::ErrorKind::WouldBlock => return Poll::Pending,
                    _ => return Poll::Ready(Err(err)),
                },
                Err(err) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("TLS shutdown error: {}", err),
                    )));
                }
            }
        }

        let inner_stream = self.inner.get_mut();

        let inner = Pin::new(&mut inner_stream.inner);

        inner.poll_shutdown(cx)
    }
}

impl<S> From<SslStream<InnerSslStream<S>>> for TlsStream<S> {
    fn from(stream: SslStream<InnerSslStream<S>>) -> TlsStream<S> {
        TlsStream { inner: stream }
    }
}

/// Type alias.
type HandshakeResult<S> = Result<SslStream<InnerSslStream<S>>, HandshakeError<InnerSslStream<S>>>;

/// A pending TLS connection.
struct TlsConnect<S> {
    handshake: Option<HandshakeResult<S>>,
}

impl<S> Future for TlsConnect<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<TlsStream<S>, TlsError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let _drop_context = set_async_context(cx);

        match self
            .handshake
            .take()
            .expect("the future has been already resolved")
        {
            Ok(stream) => Poll::Ready(Ok(stream.into())),
            Err(HandshakeError::SetupFailure(err)) => Poll::Ready(Err(TlsError::from(err))),
            Err(HandshakeError::Failure(m)) => Poll::Ready(Err(TlsError::from(m.into_error()))),
            Err(HandshakeError::WouldBlock(m)) => match m.handshake() {
                Ok(stream) => Poll::Ready(Ok(stream.into())),
                Err(HandshakeError::SetupFailure(err)) => Poll::Ready(Err(TlsError::from(err))),
                Err(HandshakeError::Failure(m)) => Poll::Ready(Err(TlsError::from(m.into_error()))),
                Err(HandshakeError::WouldBlock(m)) => {
                    self.handshake = Some(Err(HandshakeError::WouldBlock(m)));

                    Poll::Pending
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
    pub async fn connect<T>(&self, addr: T) -> Result<TlsStream<TcpStream>, TlsError>
    where
        T: ToSocketAddrs,
    {
        let stream = TcpStream::connect(addr);
        let stream = stream.await?;
        let stream = InnerSslStream::new(stream);

        let configuration = self.inner.configure()?;

        let handshake = futures::future::lazy(move |cx| {
            let _drop_context = set_async_context(cx);

            // NOTE: We do not need to validate the server name because we use only one root
            // certificate. It's a self signed certificate issued directly by Angelcam and used
            // only for Arrow.
            configuration
                .verify_hostname(false)
                .connect("hostname", stream)
        });

        let handshake = handshake.await;

        let connect = TlsConnect {
            handshake: Some(handshake),
        };

        connect.await
    }
}

impl From<SslConnector> for TlsConnector {
    fn from(connector: SslConnector) -> Self {
        Self { inner: connector }
    }
}
