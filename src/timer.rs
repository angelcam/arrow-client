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

use std::time::{Duration, Instant};

use utils::logger::{BoxLogger, Logger};

use futures::{Future, Stream};

use tokio::timer::{Delay, Deadline, Interval};

#[derive(Clone)]
pub struct Timer {
    logger: Option<BoxLogger>,
}

impl Timer {
    /// Create a new timer context.
    pub fn new(logger: Option<BoxLogger>) -> Timer {
        Timer {
            logger: logger,
        }
    }

    /// Sleep for a given period of time.
    pub fn sleep(&self, time: Duration) -> Delay {
        Delay::new(Instant::now() + time)
    }

    /// Create a timeout.
    pub fn timeout<F>(&self, future: F, timeout: Duration) -> Deadline<F>
        where F: Future {
        Deadline::new(future, Instant::now() + timeout)
    }

    /// Create a new periodic task.
    pub fn create_periodic_task<F>(&self, interval: Duration, f: F) -> impl Future<Item = (), Error = ()>
        where F: 'static + Fn() -> () {
        let logger = self.logger.clone();

        Interval::new(Instant::now() + interval, interval)
            .for_each(move |_| {
                f();

                Ok(())
            })
            .or_else(move |err| {
                if let Some(mut logger) = logger {
                    log_error!(logger, "timer error: {}", err);
                }

                Ok(())
            })
    }
}

lazy_static! {
    pub static ref DEFAULT_TIMER: Timer = Timer::new(None);
}
