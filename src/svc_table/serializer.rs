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

use std::net::{Ipv4Addr, SocketAddr};

use serde_lite::{Deserialize, Intermediate, Serialize};

use crate::{
    net::raw::ether::MacAddr,
    svc_table::{
        ServiceTableData, ServiceTableElement,
        service::{
            SVC_TYPE_CONTROL_PROTOCOL, SVC_TYPE_HTTP, SVC_TYPE_LOCKED_MJPEG, SVC_TYPE_LOCKED_RTSP,
            SVC_TYPE_MJPEG, SVC_TYPE_RTSP, SVC_TYPE_TCP, SVC_TYPE_UNKNOWN_RTSP,
            SVC_TYPE_UNSUPPORTED_RTSP, Service, ServiceType,
        },
    },
    utils::get_utc_timestamp,
};

/// Helper type for serializing/deserializing service table data.
#[derive(Deserialize, Serialize)]
pub struct ServiceTableSerializer {
    services: Vec<ServiceTableElementSerializer>,
}

impl ServiceTableSerializer {
    /// Create a new serializer from service table elements.
    pub fn new<'a, T>(services: T) -> Self
    where
        T: IntoIterator<Item = &'a ServiceTableElement>,
    {
        let services = services
            .into_iter()
            .map(ServiceTableElementSerializer::from)
            .collect();

        Self { services }
    }
}

impl From<ServiceTableSerializer> for ServiceTableData {
    fn from(serializer: ServiceTableSerializer) -> Self {
        let mut res = Self::new();

        serializer
            .services
            .into_iter()
            .enumerate()
            .for_each(|(index, svc)| {
                res.add_element(svc.into_service_table_element(index));
            });

        res
    }
}

/// Helper type for serializing/deserializing service table elements.
#[derive(Deserialize, Serialize)]
struct ServiceTableElementSerializer {
    #[serde(default)]
    id: Option<u16>,

    svc_type: ServiceTypeSerializer,
    mac: MacAddrSerializer,
    address: SocketAddrSerializer,
    path: String,

    /// Field indicating that the service was discovered via network scanning.
    #[serde(default)]
    discovered: Option<bool>,

    /// Field indicating if the service was added via the JSON-RPC API.
    #[serde(default)]
    custom: Option<bool>,

    /// Timestamp indicating when the service was discovered for the last time.
    #[serde(default)]
    last_seen: Option<i64>,

    /// Field indicating if the service was visible at the time of
    /// serialization.
    #[serde(default)]
    visible: Option<bool>,

    /// Deprecated field for backwards compatibility. Services with this flag
    /// should be treated as non-custom and non-discovered services. In other
    /// words, they should be marked as invisible after deserialization.
    #[serde(default, skip_serializing)]
    static_svc: Option<bool>,

    /// Deprecated field for backwards compatibility. It has the same meaning
    /// as the `visible` field.
    #[serde(default, skip_serializing)]
    active: Option<bool>,
}

impl ServiceTableElementSerializer {
    /// Create the corresponding `ServiceTableElement`.
    fn into_service_table_element(self, index: usize) -> ServiceTableElement {
        let mac = self.mac.into();
        let address = self.address.into();

        let epath = String::new();

        let opath = if self.path.is_empty() {
            None
        } else {
            Some(self.path)
        };

        let service = match ServiceType::from(self.svc_type) {
            ServiceType::ControlProtocol => Service::control(),
            ServiceType::RTSP => Service::rtsp(mac, address, opath.unwrap_or(epath)),
            ServiceType::LockedRTSP => Service::locked_rtsp(mac, address, opath),
            ServiceType::UnknownRTSP => Service::unknown_rtsp(mac, address),
            ServiceType::UnsupportedRTSP => {
                Service::unsupported_rtsp(mac, address, opath.unwrap_or(epath))
            }
            ServiceType::HTTP => Service::http(mac, address),
            ServiceType::MJPEG => Service::mjpeg(mac, address, opath.unwrap_or(epath)),
            ServiceType::LockedMJPEG => Service::locked_mjpeg(mac, address, opath),
            ServiceType::TCP => Service::tcp(mac, address),
        };

        let visible = if self.custom == Some(true) {
            true
        } else if self.discovered == Some(true) {
            self.visible.unwrap_or(true)
        } else if self.static_svc == Some(true) {
            false
        } else {
            self.active.unwrap_or(false)
        };

        // NOTE: All services are marked as available during deserialization.
        //   There should be an availability check before the service table is
        //   used by the rest of the system.

        ServiceTableElement {
            id: self.id.unwrap_or((index + 1) as u16),
            service,
            static_service: false,
            discovered_service: self.discovered.unwrap_or(false),
            custom_service: self.custom.unwrap_or(false),
            last_seen: self.last_seen.unwrap_or_else(get_utc_timestamp),
            visible,
            available: true,
        }
    }
}

impl From<&ServiceTableElement> for ServiceTableElementSerializer {
    fn from(elem: &ServiceTableElement) -> Self {
        let svc_type = elem.service.service_type();

        let mac = elem.service.mac().unwrap_or(MacAddr::ZERO).into();

        let address = elem
            .service
            .address()
            .unwrap_or_else(|| SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
            .into();

        let path = elem.service.path().unwrap_or("").into();

        Self {
            id: Some(elem.id),
            svc_type: svc_type.into(),
            mac,
            address,
            path,
            discovered: Some(elem.discovered_service),
            custom: Some(elem.custom_service),
            last_seen: Some(elem.last_seen),
            visible: Some(elem.visible),
            static_svc: None,
            active: None,
        }
    }
}

/// Helper type for serializing/deserializing service types.
struct ServiceTypeSerializer {
    inner: ServiceType,
}

impl Serialize for ServiceTypeSerializer {
    fn serialize(&self) -> Result<Intermediate, serde_lite::Error> {
        Ok(Intermediate::from(self.inner.code()))
    }
}

impl Deserialize for ServiceTypeSerializer {
    fn deserialize(value: &Intermediate) -> Result<Self, serde_lite::Error> {
        let inner = value
            .as_number()
            .map(u16::try_from)
            .and_then(Result::ok)
            .and_then(|code| {
                let res = match code {
                    SVC_TYPE_CONTROL_PROTOCOL => ServiceType::ControlProtocol,
                    SVC_TYPE_RTSP => ServiceType::RTSP,
                    SVC_TYPE_LOCKED_RTSP => ServiceType::LockedRTSP,
                    SVC_TYPE_UNKNOWN_RTSP => ServiceType::UnknownRTSP,
                    SVC_TYPE_UNSUPPORTED_RTSP => ServiceType::UnsupportedRTSP,
                    SVC_TYPE_HTTP => ServiceType::HTTP,
                    SVC_TYPE_MJPEG => ServiceType::MJPEG,
                    SVC_TYPE_LOCKED_MJPEG => ServiceType::LockedMJPEG,
                    SVC_TYPE_TCP => ServiceType::TCP,
                    _ => return None,
                };

                Some(res)
            })
            .ok_or_else(|| serde_lite::Error::invalid_value("service type code"))?;

        let res = Self { inner };

        Ok(res)
    }
}

impl From<ServiceType> for ServiceTypeSerializer {
    fn from(svc_type: ServiceType) -> Self {
        Self { inner: svc_type }
    }
}

impl From<ServiceTypeSerializer> for ServiceType {
    fn from(serializer: ServiceTypeSerializer) -> Self {
        serializer.inner
    }
}

/// Helper type for serializing/deserializing socket addresses.
struct SocketAddrSerializer {
    addr: SocketAddr,
}

impl Deserialize for SocketAddrSerializer {
    fn deserialize(value: &Intermediate) -> Result<Self, serde_lite::Error> {
        let addr = value
            .as_str()
            .map(|s| s.parse())
            .and_then(Result::ok)
            .ok_or_else(|| serde_lite::Error::invalid_value("socket address"))?;

        let res = Self { addr };

        Ok(res)
    }
}

impl Serialize for SocketAddrSerializer {
    fn serialize(&self) -> Result<Intermediate, serde_lite::Error> {
        Ok(Intermediate::from(self.addr.to_string()))
    }
}

impl From<SocketAddr> for SocketAddrSerializer {
    fn from(addr: SocketAddr) -> Self {
        Self { addr }
    }
}

impl From<SocketAddrSerializer> for SocketAddr {
    fn from(serializer: SocketAddrSerializer) -> Self {
        serializer.addr
    }
}

/// Helper type for serializing/deserializing MAC addresses.
struct MacAddrSerializer {
    addr: MacAddr,
}

impl Deserialize for MacAddrSerializer {
    fn deserialize(value: &Intermediate) -> Result<Self, serde_lite::Error> {
        let addr = value
            .as_str()
            .map(|s| s.parse())
            .and_then(Result::ok)
            .ok_or_else(|| serde_lite::Error::invalid_value("MAC address"))?;

        let res = Self { addr };

        Ok(res)
    }
}

impl Serialize for MacAddrSerializer {
    fn serialize(&self) -> Result<Intermediate, serde_lite::Error> {
        Ok(Intermediate::from(self.addr.to_string()))
    }
}

impl From<MacAddr> for MacAddrSerializer {
    fn from(addr: MacAddr) -> Self {
        Self { addr }
    }
}

impl From<MacAddrSerializer> for MacAddr {
    fn from(serializer: MacAddrSerializer) -> Self {
        serializer.addr
    }
}
