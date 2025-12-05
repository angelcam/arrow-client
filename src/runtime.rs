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

use std::future::Future;

/// Run a given future using a multi-threaded runtime.
#[cfg(feature = "threads")]
pub fn run<F>(future: F)
where
    F: Future<Output = ()>,
{
    tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("unable to create a tokio runtime")
        .block_on(future)
}

/// Run a given future using a single-threaded runtime.
#[cfg(not(feature = "threads"))]
pub fn run<F>(future: F)
where
    F: Future<Output = ()>,
{
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("unable to create a tokio runtime")
        .block_on(future)
}
