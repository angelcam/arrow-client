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

pub mod pipe;

use std::pin::Pin;

use futures::sink::Sink;
use futures::stream::TryStream;
use futures::task::{Context, Poll};

use self::pipe::Pipe;

/// Extension to the sink.
pub trait SinkUnpin<T>: Sink<T> {
    /// Convenience method for `Unpin` types.
    fn poll_ready_unpin(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>
    where
        Self: Unpin,
    {
        Pin::new(self).poll_ready(cx)
    }

    /// Convenience method for `Unpin` types.
    fn start_send_unpin(&mut self, item: T) -> Result<(), Self::Error>
    where
        Self: Unpin,
    {
        Pin::new(self).start_send(item)
    }

    /// Convenience method for `Unpin` types.
    fn poll_flush_unpin(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>
    where
        Self: Unpin,
    {
        Pin::new(self).poll_flush(cx)
    }

    /// Convenience method for `Unpin` types.
    fn poll_close_unpin(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>
    where
        Self: Unpin,
    {
        Pin::new(self).poll_close(cx)
    }
}

impl<T, I> SinkUnpin<I> for T where T: Sink<I> {}

/// Extension to the TryStream trait.
pub trait StreamPipe: TryStream {
    fn pipe<T>(self, other: T) -> Pipe<Self, T>
    where
        Self: Sized + Unpin,
        T: TryStream<Error = Self::Error> + Sink<Self::Ok, Error = Self::Error> + Unpin,
    {
        pipe::new(self, other)
    }
}

impl<T> StreamPipe for T where T: TryStream {}
