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

pub mod msg;
pub mod buffer;
pub mod codec;
pub mod error;

use std::io;

use std::net::ToSocketAddrs;

use futures::{StartSend, Async, AsyncSink, Poll};
use futures::future::Future;
use futures::stream::Stream;
use futures::sink::Sink;

use tokio_core::net::TcpStream;
use tokio_core::reactor::Core as TokioCore;
use tokio_core::reactor::Handle as TokioCoreHandle;

use tokio_io::AsyncRead;

use futures_ex::StreamEx;

use net::arrow::proto::codec::ArrowCodec;
use net::arrow::proto::msg::ArrowMessage;

/// Currently supported version of the Arrow protocol.
pub const ARROW_PROTOCOL_VERSION: u8 = 1;

/// Arrow Client implementation.
struct ArrowClient {
    tc_handle: TokioCoreHandle,
}

impl ArrowClient {
    /// Create a new Arrow Client.
    fn new(tc_handle: TokioCoreHandle) -> ArrowClient {
        ArrowClient {
            tc_handle: tc_handle,
        }
    }
}

impl Sink for ArrowClient {
    type SinkItem  = ArrowMessage;
    type SinkError = io::Error;

    fn start_send(&mut self, _: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        // TODO: process a given message
        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        Ok(Async::Ready(()))
    }
}

impl Stream for ArrowClient {
    type Item  = ArrowMessage;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        // TODO: return any messages that are ready to be sent
        Ok(Async::Ready(None))
    }
}

/// Connect Arrow Client to a given address.
pub fn connect(addr: &str) -> io::Result<()> {
    let mut core = TokioCore::new()?;

    let addr = addr.to_socket_addrs()?
        .next()
        .ok_or(io::Error::new(io::ErrorKind::Other, "unable to resolve a given address"))?;

    let aclient = ArrowClient::new(core.handle());

    let client = TcpStream::connect(&addr, &core.handle())
        .and_then(|stream| {
            let framed = stream.framed(ArrowCodec);
            let (sink, stream) = framed.split();

            let messages = stream.pipe(aclient);

            sink.send_all(messages)
                .and_then(|_| {
                    Ok(())
                })
        });

    core.run(client)
}
