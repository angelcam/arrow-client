// Copyright 2019 Angelcam, Inc.
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

#[cfg(feature = "threads")]
use std::time::Duration;

use futures::{Async, Future, Poll};

use tokio;

#[cfg(feature = "threads")]
use tokio_threadpool;

/// Run a given future using a multi-threaded runtime.
#[cfg(feature = "threads")]
pub fn run<F>(future: F)
where
    F: 'static + Future<Item = (), Error = ()> + Send,
{
    tokio::runtime::Builder::new()
        .keep_alive(Some(Duration::from_secs(30)))
        .build()
        .expect("unable to create a tokio runtime")
        .block_on(future)
        .unwrap_or(())
}

/// Run a given future using a single-threaded runtime.
#[cfg(not(feature = "threads"))]
pub fn run<F>(future: F)
where
    F: 'static + Future<Item = (), Error = ()> + Send,
{
    tokio::runtime::current_thread::Runtime::new()
        .expect("unable to create a tokio runtime")
        .block_on(future)
        .unwrap_or(())
}

/// Run a given closure as blocking.
#[cfg(feature = "threads")]
pub fn blocking<F, T>(f: F) -> Poll<T, ()>
where
    F: FnOnce() -> T,
{
    let res = tokio_threadpool::blocking(f);

    match res.unwrap() {
        Async::Ready(item) => Ok(Async::Ready(item)),
        Async::NotReady => Ok(Async::NotReady),
    }
}

/// Run a given closure as blocking.
#[cfg(not(feature = "threads"))]
pub fn blocking<F, T>(f: F) -> Poll<T, ()>
where
    F: FnOnce() -> T,
{
    Ok(Async::Ready(f()))
}
