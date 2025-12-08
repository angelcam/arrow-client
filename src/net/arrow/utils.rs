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

use std::{
    io,
    mem::MaybeUninit,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use futures::{Sink, Stream, ready};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pin_project_lite::pin_project! {
    /// Async IO wrapper implementing `Stream` and `Sink`.
    pub struct StreamedIO<T> {
        #[pin]
        inner_io: T,
        pending_write: Bytes,
    }
}

impl<T> StreamedIO<T> {
    /// Create a new streamed IO.
    pub fn new(io: T) -> Self {
        Self {
            inner_io: io,
            pending_write: Bytes::new(),
        }
    }
}

impl<T> Stream for StreamedIO<T>
where
    T: AsyncRead,
{
    type Item = io::Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        let mut buffer: [MaybeUninit<u8>; 8_192] = unsafe { MaybeUninit::uninit().assume_init() };

        let mut buffer = ReadBuf::uninit(&mut buffer);

        ready!(this.inner_io.poll_read(cx, &mut buffer))?;

        let filled = buffer.filled();

        if filled.is_empty() {
            Poll::Ready(None)
        } else {
            Poll::Ready(Some(Ok(Bytes::copy_from_slice(filled))))
        }
    }
}

impl<T> Sink<Bytes> for StreamedIO<T>
where
    T: AsyncWrite,
{
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let mut this = self.project();

        loop {
            if this.pending_write.is_empty() {
                return Poll::Ready(Ok(()));
            }

            let io = this.inner_io.as_mut();

            let len = ready!(io.poll_write(cx, this.pending_write))?;

            this.pending_write.advance(len);
        }
    }

    fn start_send(self: Pin<&mut Self>, chunk: Bytes) -> Result<(), Self::Error> {
        assert!(self.pending_write.is_empty());

        let this = self.project();

        *this.pending_write = chunk;

        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(Sink::poll_ready(self.as_mut(), cx))?;

        let this = self.project();

        this.inner_io.poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(Sink::poll_ready(self.as_mut(), cx))?;

        let this = self.project();

        this.inner_io.poll_shutdown(cx)
    }
}
