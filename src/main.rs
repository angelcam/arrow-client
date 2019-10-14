// Copyright 2015 click2stream, Inc.
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

use std::error::Error;
use std::fmt::Debug;

use arrow_client::runtime;

use arrow_client::client::ArrowClient;
use arrow_client::config::Config;

use arrow_client::config::usage;

/// Unwrap a given result (if possible) or print the error message and exit
/// the process printing application usage.
fn result_or_usage<T, E>(res: Result<T, E>) -> T
where
    E: Error + Debug,
{
    match res {
        Ok(res) => res,
        Err(err) => {
            println!("ERROR: {}\n", err);
            usage(1);
        }
    }
}

/// Arrow Client main function.
fn main() {
    let config = result_or_usage(Config::from_args(std::env::args()));

    let (_, task) = ArrowClient::new(config);

    runtime::run(task);
}
