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

use context::ApplicationContext;

use futures::{BoxFuture, Future, Poll, Stream};

use futures::sync::mpsc;
use futures::sync::mpsc::{UnboundedReceiver, UnboundedSender};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Command {
    ResetServiceTable,
    ScanNetwork,
}

type CommandReceiver = UnboundedReceiver<Command>;

type CommandSender = UnboundedSender<Command>;

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
        self.tx.send(cmd)
            .expect("broken command channel");
    }
}

/// Command handler context.
struct CommandHandlerContext {
    app_context: ApplicationContext,
}

impl CommandHandlerContext {
    /// Create a new command handler context.
    fn new(app_context: ApplicationContext) -> CommandHandlerContext {
        CommandHandlerContext {
            app_context: app_context,
        }
    }

    /// Process a given command.
    fn process_command(&mut self, cmd: Command) {
        // TODO
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

        let handler = rx.for_each(move |cmd| {
            context.process_command(cmd);
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
