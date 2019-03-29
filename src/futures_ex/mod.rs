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

use futures::sink::Sink;
use futures::stream::Stream;

use self::pipe::Pipe;

/// Extension to the Stream trait.
pub trait StreamEx: Stream {
    fn pipe<T>(self, other: T) -> Pipe<Self, T>
    where
        T: Stream + Sink<SinkItem = Self::Item>,
        T::SinkError: From<Self::Error>,
        T::Error: From<T::SinkError>,
        Self: Sized,
    {
        pipe::new(self, other)
    }
}

impl<T: Stream> StreamEx for T {}
