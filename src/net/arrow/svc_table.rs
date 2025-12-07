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
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use arrow_protocol::v3::ControlProtocolClientConnectionHandle;
use serde_lite::Serialize;

use crate::{
    error::Error,
    net::raw::ether::MacAddr,
    svc_table::{Service, ServiceTableHandle, ServiceType},
};

const UPDATE_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// Service table updater.
pub struct ServiceTableUpdater {
    connection: ControlProtocolClientConnectionHandle,
    svc_table: ServiceTableHandle,
    last_reported_version: Option<u32>,
}

impl ServiceTableUpdater {
    /// Create a new service table updater.
    pub fn new(
        svc_table: ServiceTableHandle,
        connection: ControlProtocolClientConnectionHandle,
    ) -> Self {
        Self {
            connection,
            svc_table,
            last_reported_version: None,
        }
    }

    /// Run the service table updater.
    pub async fn run(mut self) {
        while self.send_update().await.is_ok() {
            tokio::time::sleep(UPDATE_CHECK_INTERVAL).await;
        }
    }

    /// Send a service table update if needed.
    async fn send_update(&mut self) -> Result<(), Error> {
        // helper struct
        #[derive(Serialize)]
        struct Params {
            services: Vec<ServiceTableElement>,
        }

        let current_version = self.svc_table.visible_set_version();

        if self.last_reported_version == Some(current_version) {
            return Ok(());
        }

        self.last_reported_version = Some(current_version);

        let mut params = Params {
            services: Vec::new(),
        };

        for (service_id, service) in self.svc_table.visible() {
            params
                .services
                .push(ServiceTableElement::new(service_id, &service));
        }

        let msg = params
            .serialize()
            .expect("unable to serialize service table");

        debug!("sending service table update...");

        self.connection
            .send_notification("update_service_table", msg)
            .await
            .map_err(Error::from_other)
    }
}

/// Scan report service entry.
#[derive(Serialize)]
pub struct ServiceTableElement {
    service_id: u16,
    #[serde(rename = "type")]
    kind: &'static str,
    mac: String,
    host: String,
    port: u16,
    path: String,
}

impl ServiceTableElement {
    /// Create a new service table element.
    pub fn new(service_id: u16, service: &Service) -> Self {
        let kind = match service.service_type() {
            ServiceType::ControlProtocol => "control",
            ServiceType::RTSP => "rtsp",
            ServiceType::LockedRTSP => "rtsp_locked",
            ServiceType::UnknownRTSP => "rtsp_unknown",
            ServiceType::UnsupportedRTSP => "rtsp_unsupported",
            ServiceType::HTTP => "http",
            ServiceType::MJPEG => "mjpeg",
            ServiceType::LockedMJPEG => "mjpeg_locked",
            ServiceType::TCP => "tcp",
        };

        let mac = service.mac().unwrap_or(MacAddr::ZERO).to_string();
        let host = service
            .ip_address()
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
            .to_string();
        let port = service.port().unwrap_or(0);
        let path = service.path().unwrap_or("").to_string();

        Self {
            service_id,
            kind,
            mac,
            host,
            port,
            path,
        }
    }
}
