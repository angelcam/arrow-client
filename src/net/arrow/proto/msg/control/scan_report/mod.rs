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

mod host_table;

use std::mem;

use bytes::BytesMut;

use utils;

use net::arrow::proto::codec::Encode;
use net::arrow::proto::msg::MessageBody;
use net::arrow::proto::msg::control::ControlMessageBody;
use net::arrow::proto::msg::control::SimpleServiceTable;

use scanner::ScanResult;

use svc_table::ServiceTable;

use self::host_table::HostTable;

/// SCAN_REPORT message header.
#[repr(packed)]
struct ScanReportMessageHeader {
    request_id: u16,
}

impl<'a> From<&'a ScanReportMessage> for ScanReportMessageHeader {
    fn from(message: &'a ScanReportMessage) -> ScanReportMessageHeader {
        ScanReportMessageHeader {
            request_id: message.request_id,
        }
    }
}

impl Encode for ScanReportMessageHeader {
    fn encode(&self, buf: &mut BytesMut) {
        let be_header = ScanReportMessageHeader {
            request_id: self.request_id.to_be(),
        };

        buf.extend_from_slice(utils::as_bytes(&be_header))
    }
}

/// SCAN_REPORT message.
pub struct ScanReportMessage {
    request_id:  u16,
    host_table:  HostTable,
    svc_table:   SimpleServiceTable,
}

impl ScanReportMessage {
    /// Create a new SCAN_REPORT message.
    pub fn new<T>(
        request_id: u16,
        scan_result: ScanResult,
        svc_table: &T) -> ScanReportMessage
        where T: ServiceTable {
        let hosts = scan_result.hosts()
            .map(|host| host.clone());

        let host_table = HostTable::from(hosts);

        let mut services = Vec::new();

        for svc in scan_result.services() {
            if let Some(id) = svc_table.get_id(&svc.to_service_identifier()) {
                services.push((id, svc.clone()));
            }
        }

        let svc_table = SimpleServiceTable::from(services);

        ScanReportMessage {
            request_id: request_id,
            host_table: host_table,
            svc_table:  svc_table,
        }
    }
}

impl Encode for ScanReportMessage {
    fn encode(&self, buf: &mut BytesMut) {
        ScanReportMessageHeader::from(self)
            .encode(buf);

        self.host_table.encode(buf);
        self.svc_table.encode(buf);
    }
}

impl MessageBody for ScanReportMessage {
    fn len(&self) -> usize {
        mem::size_of::<ScanReportMessageHeader>()
            + self.host_table.len()
            + self.svc_table.len()
    }
}

impl ControlMessageBody for ScanReportMessage {
}
