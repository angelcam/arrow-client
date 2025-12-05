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

mod runtime;

use arrow_client::{client::ArrowClient, config::Config};

/// Arrow Client main function.
fn main() {
    let config = match Config::from_args() {
        Ok(config) => config,
        Err(err) => {
            println!("ERROR: {}\n", err);

            arrow_client::config::usage(1);
        }
    };

    let (client, task) = ArrowClient::new(config);

    // forget the client, we want to run the application indefinitely
    std::mem::forget(client);

    runtime::run(task);
}
