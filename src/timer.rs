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

use std::sync::{Arc, Mutex};
use std::time::Duration;

use utils::logger::{BoxLogger, Logger};

use futures::{Future, Poll, Stream};

use tokio_timer::{Timeout, TimeoutError};
use tokio_timer::Timer as TokioTimer;

pub struct PeriodicTask {
    task: Box<Future<Item=(), Error=()>>,
}

impl Future for PeriodicTask {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.task.poll()
    }
}

struct TimerContext {
    logger: Option<BoxLogger>,
    timer:  TokioTimer,
}

impl TimerContext {
    /// Create a new timer context.
    fn new(logger: Option<BoxLogger>) -> TimerContext {
        let timer = TokioTimer::default();

        TimerContext {
            logger: logger,
            timer:  timer,
        }
    }

    /// Create a timeout.
    fn timeout<F, E>(&self, future: F, timeout: Duration) -> Timeout<F>
        where F: Future<Error=E>,
              E: From<TimeoutError<F>> {
        self.timer.timeout(future, timeout)
    }

    /// Create a new periodic task.
    fn create_periodic_task<F>(&self, interval: Duration, f: F) -> PeriodicTask
        where F: 'static + Fn() -> () {
        let logger = self.logger.clone();

        let task = self.timer.interval(interval)
            .for_each(move |_| {
                f();

                Ok(())
            })
            .or_else(move |err| {
                if let Some(mut logger) = logger {
                    log_error!(logger, "timer error: {}", err);
                }

                Ok(())
            });

        PeriodicTask {
            task: Box::new(task),
        }
    }
}

#[derive(Clone)]
pub struct Timer {
    context: Arc<Mutex<TimerContext>>,
}

impl Timer {
    /// Create a new timer context.
    pub fn new(logger: Option<BoxLogger>) -> Timer {
        Timer {
            context: Arc::new(Mutex::new(TimerContext::new(logger))),
        }
    }

    /// Create a timeout.
    pub fn timeout<F, E>(&self, future: F, timeout: Duration) -> Timeout<F>
        where F: Future<Error=E>,
              E: From<TimeoutError<F>> {
        self.context.lock()
            .unwrap()
            .timeout(future, timeout)
    }

    /// Create a new periodic task.
    pub fn create_periodic_task<F>(&self, interval: Duration, f: F) -> PeriodicTask
        where F: 'static + Fn() -> () {
        self.context.lock()
            .unwrap()
            .create_periodic_task(interval, f)
    }
}

lazy_static! {
    pub static ref DEFAULT_TIMER: Timer = Timer::new(None);
}
