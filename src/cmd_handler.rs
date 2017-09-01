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

#[cfg(feature="discovery")]
use std::thread;

use std::thread::JoinHandle;

use context::ApplicationContext;

#[cfg(feature = "discovery")]
use scanner::discovery;

#[cfg(feature="discovery")]
use utils;

use utils::logger::{BoxedLogger, Logger};

#[cfg(feature="discovery")]
use utils::logger::Severity;

use futures::{BoxFuture, Future, Poll, Stream};

use futures::sync::mpsc;
use futures::sync::mpsc::{UnboundedReceiver, UnboundedSender};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Command {
    ResetServiceTable,
    ScanNetwork,
}

#[derive(Debug, Copy, Clone)]
enum Event {
    Command(Command),
    ScanCompleted,
}

type CommandReceiver = UnboundedReceiver<Event>;

type CommandSender = UnboundedSender<Event>;

/// A channel for sending commands across threads. The channel is cloneable and every copy of it
/// will send commands to the same handler.
#[derive(Clone)]
pub struct CommandChannel {
    tx: CommandSender,
}

impl CommandChannel {
    /// Create a new command channel.
    fn new(tx: CommandSender) -> CommandChannel {
        CommandChannel {
            tx: tx,
        }
    }

    /// Send a given command.
    pub fn send(&self, cmd: Command) {
        self.tx.send(Event::Command(cmd))
            .expect("broken command channel");
    }
}

/// Command handler context.
struct CommandHandlerContext {
    app_context: ApplicationContext,
    logger:      BoxedLogger,
    scanner:     Option<JoinHandle<()>>,
}

impl CommandHandlerContext {
    /// Create a new command handler context.
    fn new(app_context: ApplicationContext) -> CommandHandlerContext {
        let logger = app_context.get_logger();

        CommandHandlerContext {
            app_context: app_context,
            logger:      logger,
            scanner:     None,
        }
    }

    /// Process a given command handler event.
    fn proces_event(&mut self, event: Event) {
        match event {
            Event::Command(cmd)  => self.process_command(cmd),
            Event::ScanCompleted => self.scan_completed(),
        }
    }

    /// Process a given command.
    fn process_command(&mut self, cmd: Command) {
        match cmd {
            Command::ResetServiceTable => self.reset_service_table(),
            Command::ScanNetwork       => self.scan_network(),
        }
    }

    /// Reset service table.
    fn reset_service_table(&mut self) {
        self.app_context.reset_service_table()
    }

    #[cfg(feature="discovery")]
    /// Trigger a network scan.
    fn scan_network(&mut self) {
        if self.scanner.is_some() {
            return;
        }

        let app_context = self.app_context.clone();

        let handle = thread::spawn(move || {
            network_scanner_thread(app_context);
        });

        self.scanner = Some(handle);
    }

    #[cfg(not(feature="discovery"))]
    /// Dummy network scan.
    fn scan_network(&mut self) {
    }

    /// Cleanup the scanner context.
    fn scan_completed(&mut self) {
        if let Some(handle) = self.scanner.take() {
            if let Err(_) = handle.join() {
                log_warn!(self.logger, "network scanner thread panicked");
            }
        }
    }
}

/// Command handler. It implements the future trait and it's designed to be used in combination
/// with tokio event loop.
pub struct CommandHandler {
    handler: BoxFuture<(), ()>,
}

impl CommandHandler {
    /// Create a new command handler.
    fn new(app_context: ApplicationContext, rx: CommandReceiver) -> CommandHandler {
        let mut context = CommandHandlerContext::new(app_context);

        let handler = rx.for_each(move |event| {
            context.proces_event(event);
            Ok(())
        });

        CommandHandler {
            handler: handler.boxed(),
        }
    }
}

impl Future for CommandHandler {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.handler.poll()
    }
}

/// Create a new channel-handler pair.
pub fn new(app_context: ApplicationContext) -> (CommandChannel, CommandHandler) {
    let (tx, rx) = mpsc::unbounded();

    let rx = CommandHandler::new(app_context, rx);
    let tx = CommandChannel::new(tx);

    (tx, rx)
}

#[cfg(feature = "discovery")]
/// Run device discovery and update the service table.
fn network_scanner_thread(mut app_context: ApplicationContext) {
    let mut logger = app_context.get_logger();

    let rtsp_paths_file = app_context.get_rtsp_paths_file();
    let mjpeg_paths_file = app_context.get_mjpeg_paths_file();

    app_context.set_scanning(true);

    log_info!(logger, "looking for local services...");

    let result = utils::result_or_log(&mut logger, Severity::WARN,
        "network scanner error",
        discovery::scan_network(
            &rtsp_paths_file,
            &mjpeg_paths_file));

    if let Some(result) = result {
        let services = result.services()
            .map(|svc| svc.clone())
            .collect::<Vec<_>>();

        let count = services.len();

        app_context.update_service_table(services);
        app_context.set_scan_result(result);

        log_info!(logger, "{} services found, current service table: {}",
            count, app_context.get_service_table());
    }

    app_context.set_scanning(false);
}
