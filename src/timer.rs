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

use std;
use std::thread;

use std::time::{Duration, Instant};

use utils::logger::{BoxLogger, Logger};

use futures::{Future, Stream};

use tokio_timer::{Delay, Deadline};
use tokio_timer::timer::Handle as TokioTimerHandle;
use tokio_timer::timer::Timer as TokioTimer;

#[derive(Clone)]
pub struct Timer {
    logger: Option<BoxLogger>,
    handle: TokioTimerHandle,
}

impl Timer {
    /// Create a new timer context.
    pub fn new(mut logger: Option<BoxLogger>) -> Timer {
        let (tx, rx) = std::sync::mpsc::channel::<TokioTimerHandle>();

        let lgr = logger.clone();

        thread::spawn(move || {
            let mut timer = TokioTimer::default();

            tx.send(timer.handle())
                .expect("broken mpsc channel");

            loop {
                if let Err(_) = timer.turn(None) {
                    if let Some(logger) = logger.as_mut() {
                        log_error!(logger, "timer thread error");
                    }

                    panic!("timer thread error");
                }
            }
        });

        let handle = rx.recv()
            .expect("broken mpsc channel");

        Timer {
            logger: lgr,
            handle: handle,
        }
    }

    /// Sleep for a given period of time.
    pub fn sleep(&self, time: Duration) -> Delay {
        self.handle.delay(Instant::now() + time)
    }

    /// Create a timeout.
    pub fn timeout<F>(&self, future: F, timeout: Duration) -> Deadline<F>
        where F: Future {
        self.handle.deadline(future, Instant::now() + timeout)
    }

    /// Create a new periodic task.
    pub fn create_periodic_task<F>(&self, interval: Duration, f: F) -> impl Future<Item = (), Error = ()>
        where F: 'static + Fn() -> () {
        let logger = self.logger.clone();

        self.handle.interval(Instant::now() + interval, interval)
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
