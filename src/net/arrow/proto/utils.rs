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

use std::rc::Rc;
use std::cell::Cell;

use net::arrow::proto::{ServiceTable, ScanReport};
use net::arrow::proto::msg::ControlMessage;

use net::raw::ether::MacAddr;

/// Control Protocol message factory with shared message ID counter.
#[derive(Clone)]
pub struct ControlMessageFactory {
    counter: Rc<Cell<u16>>,
}

impl ControlMessageFactory {
    /// Create a new Control Protocol message factory.
    pub fn new() -> ControlMessageFactory {
        ControlMessageFactory {
            counter: Rc::new(Cell::new(0)),
        }
    }

    /// Get next message ID and increment the counter.
    fn next_id(&mut self) -> u16 {
        let res = self.counter.get();

        self.counter.set(res.wrapping_add(1));

        res
    }

    /// Create a new ACK message with a given error code.
    pub fn ack(&mut self, msg_id: u16, error_code: u32) -> ControlMessage {
        ControlMessage::ack(
            msg_id,
            error_code)
    }

    /// Create a new HUP message with a given session ID and error code.
    pub fn hup(&mut self, session_id: u32, error_code: u32) -> ControlMessage {
        ControlMessage::hup(
            self.next_id(),
            session_id,
            error_code)
    }

    /// Create a new STATUS message with a given request ID, flags and number
    /// of active sessions.
    pub fn status(
        &mut self,
        request_id: u16,
        status_flags: u32,
        active_sessions: u32) -> ControlMessage {
        ControlMessage::status(
            self.next_id(),
            request_id,
            status_flags,
            active_sessions)
    }

    /// Create a new SCAN_REPORT message for a given scan report.
    pub fn scan_report(
        &mut self,
        request_id: u16,
        report: ScanReport) -> ControlMessage {
        ControlMessage::scan_report(
            self.next_id(),
            request_id,
            report)
    }

    /// Create a new PING message.
    pub fn ping(&mut self) -> ControlMessage {
        ControlMessage::ping(
            self.next_id())
    }

    /// Create a new REGISTER message.
    pub fn register<T>(
        &mut self,
        mac: MacAddr,
        uuid: [u8; 16],
        password: [u8; 16],
        svc_table: &T) -> ControlMessage
        where T: ServiceTable {
        ControlMessage::register(
            self.next_id(),
            mac,
            uuid,
            password,
            svc_table)
    }
}
