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

use std::pin::Pin;

use futures::ready;
use futures::sink::Sink;
use futures::stream::{Fuse, IntoStream, Stream, StreamExt, TryStream, TryStreamExt};
use futures::task::{Context, Poll};

use crate::futures_ex::SinkUnpin;

/// Implementation of the Stream pipe operation.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Pipe<T, U>
where
    T: TryStream,
{
    stream: Fuse<IntoStream<T>>,
    sink: IntoStream<U>,
    buffered: Option<T::Ok>,
}

/// Create a new Pipe object.
pub fn new<T, U>(stream: T, sink: U) -> Pipe<T, U>
where
    T: TryStream + Unpin,
    U: TryStream<Error = T::Error> + Sink<T::Ok, Error = T::Error> + Unpin,
{
    Pipe {
        stream: stream.into_stream().fuse(),
        sink: sink.into_stream(),
        buffered: None,
    }
}

impl<T, U> Pipe<T, U>
where
    Self: Unpin,
    T: TryStream + Unpin,
    U: TryStream<Error = T::Error> + Sink<T::Ok, Error = T::Error> + Unpin,
{
    /// Break the pipe and return the stream, sink and any possibly buffered object.
    pub fn unpipe(self) -> (Option<T::Ok>, T, U) {
        (
            self.buffered,
            self.stream.into_inner().into_inner(),
            self.sink.into_inner(),
        )
    }

    fn poll_stream_item(&mut self, cx: &mut Context) -> Poll<Option<Result<T::Ok, T::Error>>> {
        // take the buffered item if there is one
        if let Some(item) = self.buffered.take() {
            return Poll::Ready(Some(Ok(item)));
        }

        self.stream.poll_next_unpin(cx)
    }

    fn try_send_stream_item(
        &mut self,
        cx: &mut Context,
        item: T::Ok,
    ) -> Poll<Result<(), T::Error>> {
        match self.sink.poll_ready_unpin(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(self.sink.start_send_unpin(item)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => {
                self.buffered = Some(item);
                Poll::Pending
            }
        }
    }

    fn feed_sink(&mut self, cx: &mut Context) -> Poll<Result<(), T::Error>> {
        if let Some(item) = ready!(self.poll_stream_item(cx)) {
            match item {
                Ok(item) => self.try_send_stream_item(cx, item),
                Err(err) => Poll::Ready(Err(err)),
            }
        } else {
            self.sink.poll_close_unpin(cx)
        }
    }
}

impl<T, U> Stream for Pipe<T, U>
where
    Self: Unpin,
    T: TryStream + Unpin,
    U: TryStream<Error = T::Error> + Sink<T::Ok, Error = T::Error> + Unpin,
{
    type Item = Result<U::Ok, <U as TryStream>::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        // make sure that we feed the sink at least once on every poll to avoid
        // congestion of the input stream
        if let Poll::Ready(Err(err)) = self.feed_sink(cx) {
            return Poll::Ready(Some(Err(err)));
        }

        loop {
            // try to poll the output stream...
            match self.sink.poll_next_unpin(cx) {
                Poll::Ready(Some(item)) => return Poll::Ready(Some(item)),
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => (),
            }

            // ... if it's pending, try to feed the sink again
            match self.feed_sink(cx) {
                Poll::Ready(Ok(())) => (),
                Poll::Ready(Err(err)) => return Poll::Ready(Some(Err(err))),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
