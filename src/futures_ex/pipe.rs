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

use futures::{Async, AsyncSink, Poll, StartSend};
use futures::stream::{Fuse, Stream};
use futures::sink::Sink;

/// Implementation of the Stream pipe operation.
#[derive(Debug)]
#[must_use = "streams do nothing unless polled"]
pub struct Pipe<T: Stream, U> {
    stream:   Fuse<T>,
    sink:     U,
    buffered: Option<T::Item>,
}

/// Create a new Pipe object.
pub fn new<T, U>(stream: T, sink: U) -> Pipe<T, U>
    where T: Stream,
          U: Stream + Sink<SinkItem=T::Item>,
          U::SinkError: From<T::Error>,
          U::Error: From<U::SinkError>,
{
    Pipe {
        stream:   stream.fuse(),
        sink:     sink,
        buffered: None,
    }
}

impl<T, U> Pipe<T, U>
    where T: Stream,
          U: Stream + Sink<SinkItem=T::Item>,
          U::SinkError: From<T::Error>,
          U::Error: From<U::SinkError>,
{
    /// Break the pipe and return the stream, sink and any possibly buffered object.
    pub fn unpipe(self) -> (Option<T::Item>, T, U) {
        (self.buffered, self.stream.into_inner(), self.sink)
    }

    fn poll_stream_item(&mut self) -> Poll<Option<T::Item>, T::Error> {
        // take the buffered item if there is one
        if let Some(item) = self.buffered.take() {
            return Ok(Async::Ready(Some(item)))
        }

        self.stream.poll()
    }

    fn try_start_send(&mut self, item: T::Item) -> Poll<(), U::SinkError> {
        debug_assert!(self.buffered.is_none());
        if let AsyncSink::NotReady(item) = try!(self.sink.start_send(item)) {
            self.buffered = Some(item);
            return Ok(Async::NotReady)
        }
        Ok(Async::Ready(()))
    }

    fn feed_sink(&mut self) -> Poll<(), U::SinkError> {
        loop {
            match try!(self.poll_stream_item()) {
                Async::Ready(Some(item)) => try_ready!(self.try_start_send(item)),
                Async::Ready(None)       => return self.sink.close(),
                Async::NotReady          => return self.sink.poll_complete()
            }
        }
    }
}

impl<T, U> Stream for Pipe<T, U>
    where T: Stream,
          U: Stream + Sink<SinkItem=T::Item>,
          U::SinkError: From<T::Error>,
          U::Error: From<U::SinkError>,
{
    type Item = U::Item;
    type Error = U::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        // feed the internal sink
        try!(self.feed_sink());

        // retrieve the next item from the sink stream
        self.sink.poll()
    }
}

impl<T, U> Sink for Pipe<T, U>
where T: Stream + Sink,
      U: Stream + Sink<SinkItem=T::Item>,
      U::SinkError: From<T::Error>,
      U::Error: From<U::SinkError>,
{
    type SinkItem  = T::SinkItem;
    type SinkError = T::SinkError;

    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        self.stream.start_send(item)
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        self.stream.poll_complete()
    }
}
