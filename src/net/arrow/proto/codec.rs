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

use std::io;

use bytes::BytesMut;
use tokio_io::codec::{Decoder, Encoder};

use net::arrow::proto::{Decode, Encode};
use net::arrow::proto::msg::ArrowMessage;

/// ArrowMessage codec used in tokio.
pub struct ArrowCodec;

impl Decoder for ArrowCodec {
    // TODO: we should probably use a custom error type here
    type Item  = ArrowMessage;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        ArrowMessage::decode(src)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
    }
}

impl Encoder for ArrowCodec {
    // TODO: we should probably use a custom error type here
    type Item  = ArrowMessage;
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        item.encode(dst);
        Ok(())
    }
}
