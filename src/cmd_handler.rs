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

use std::{
    pin::Pin,
    task::{Context, Poll},
    thread::JoinHandle,
    time::{Duration, Instant},
};

use futures::{
    FutureExt, StreamExt,
    channel::mpsc::{self, UnboundedReceiver, UnboundedSender},
};

use crate::context::ApplicationContext;

#[cfg(feature = "discovery")]
use crate::{scanner::discovery, svc_table::ServiceSource};

/// Network scan period.
const NETWORK_SCAN_PERIOD: Duration = Duration::from_secs(300);

/// Different command types that the command handler can receive.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Command {
    ResetServiceTable,
    ScanNetwork,
    PeriodicNetworkScan,
}

/// Command handler event.
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
    fn new(tx: CommandSender) -> Self {
        Self { tx }
    }

    /// Send a given command.
    pub fn send(&self, cmd: Command) {
        self.tx
            .unbounded_send(Event::Command(cmd))
            .expect("broken command channel");
    }
}

/// Command handler context.
struct CommandHandlerContext {
    app_context: ApplicationContext,
    cmd_sender: CommandSender,
    last_nw_scan: Option<Instant>,
    scanner: Option<JoinHandle<()>>,
}

impl CommandHandlerContext {
    /// Create a new command handler context.
    fn new(app_context: ApplicationContext, cmd_sender: CommandSender) -> Self {
        Self {
            app_context,
            cmd_sender,
            last_nw_scan: None,
            scanner: None,
        }
    }

    /// Process a given command handler event.
    fn proces_event(&mut self, event: Event) {
        match event {
            Event::Command(cmd) => self.process_command(cmd),
            Event::ScanCompleted => self.scan_completed(),
        }
    }

    /// Process a given command.
    fn process_command(&mut self, cmd: Command) {
        match cmd {
            Command::ResetServiceTable => self.reset_service_table(),
            Command::ScanNetwork => self.scan_network(),
            Command::PeriodicNetworkScan => self.periodic_network_scan(),
        }
    }

    /// Reset service table.
    fn reset_service_table(&mut self) {
        self.app_context.reset_service_table()
    }

    /// Trigger periodic netork scan.
    fn periodic_network_scan(&mut self) {
        let time_since_last_nw_scan = self
            .last_nw_scan
            .map(|i| i.elapsed())
            .unwrap_or(NETWORK_SCAN_PERIOD);

        if time_since_last_nw_scan >= NETWORK_SCAN_PERIOD {
            self.scan_network();
        }
    }

    #[cfg(feature = "discovery")]
    /// Trigger a network scan.
    fn scan_network(&mut self) {
        let interfaces = self.app_context.get_discovery_interfaces();

        if interfaces.is_empty() || self.scanner.is_some() {
            return;
        }

        let app_context = self.app_context.clone();
        let cmd_sender = self.cmd_sender.clone();

        let handle = std::thread::spawn(move || {
            network_scanner_thread(app_context);

            cmd_sender.unbounded_send(Event::ScanCompleted).unwrap();
        });

        self.scanner = Some(handle);
    }

    #[cfg(not(feature = "discovery"))]
    /// Dummy network scan.
    fn scan_network(&mut self) {
        self.cmd_sender
            .unbounded_send(Event::ScanCompleted)
            .unwrap();
    }

    /// Cleanup the scanner context.
    fn scan_completed(&mut self) {
        if let Some(handle) = self.scanner.take() {
            let res = handle.join();

            if res.is_err() {
                warn!("network scanner thread panicked");
            }
        }

        self.last_nw_scan = Some(Instant::now());
    }
}

/// Command handler. It implements the future trait and it's designed to be used in combination
/// with tokio event loop.
pub struct CommandHandler {
    inner: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl CommandHandler {
    /// Create a new command handler.
    fn new(app_context: ApplicationContext, mut rx: CommandReceiver, tx: CommandSender) -> Self {
        let mut context = CommandHandlerContext::new(app_context, tx);

        let handler = async move {
            while let Some(event) = rx.next().await {
                context.proces_event(event);
            }
        };

        Self {
            inner: handler.boxed(),
        }
    }
}

impl Future for CommandHandler {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        self.inner.poll_unpin(cx)
    }
}

/// Create a new channel-handler pair.
pub fn new(app_context: ApplicationContext) -> (CommandChannel, CommandHandler) {
    let (tx, rx) = mpsc::unbounded();

    let rx = CommandHandler::new(app_context, rx, tx.clone());
    let tx = CommandChannel::new(tx);

    (tx, rx)
}

#[cfg(feature = "discovery")]
/// Run device discovery and update the service table.
fn network_scanner_thread(mut app_context: ApplicationContext) {
    let discovery_whitelist = app_context.get_discovery_interfaces();
    let rtsp_paths = app_context.get_rtsp_paths();
    let mjpeg_paths = app_context.get_mjpeg_paths();

    app_context.set_scanning(true);

    info!("looking for local services...");

    let result = discovery::scan_network(discovery_whitelist, rtsp_paths, mjpeg_paths)
        .inspect_err(|err| warn!("network scanner error ({err})"));

    if let Ok(result) = result {
        let services = result.services().cloned().collect::<Vec<_>>();

        let count = services.len();

        app_context.update_service_table(services, ServiceSource::Discovery);
        app_context.set_scan_result(result);

        info!(
            "{} services found, current service table: {}",
            count,
            app_context.get_service_table()
        );
    }

    app_context.set_scanning(false);
}
