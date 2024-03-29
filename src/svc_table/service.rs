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

use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};

use crate::net::raw::ether::MacAddr;

pub const SVC_TYPE_CONTROL_PROTOCOL: u16 = 0x0000;
pub const SVC_TYPE_RTSP: u16 = 0x0001;
pub const SVC_TYPE_LOCKED_RTSP: u16 = 0x0002;
pub const SVC_TYPE_UNKNOWN_RTSP: u16 = 0x0003;
pub const SVC_TYPE_UNSUPPORTED_RTSP: u16 = 0x0004;
pub const SVC_TYPE_HTTP: u16 = 0x0005;
pub const SVC_TYPE_MJPEG: u16 = 0x0006;
pub const SVC_TYPE_LOCKED_MJPEG: u16 = 0x0007;
pub const SVC_TYPE_TCP: u16 = 0xffff;

/// Service type.
#[allow(clippy::upper_case_acronyms)]
#[repr(u32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum ServiceType {
    /// Control Protocol service.
    ControlProtocol,
    /// Remote RTSP service.
    RTSP,
    /// Remote RTSP service requiring authentication.
    LockedRTSP,
    /// Remote RTSP service without any known path.
    UnknownRTSP,
    /// Remote RTSP service without any supported stream.
    UnsupportedRTSP,
    /// Remote HTTP service.
    HTTP,
    /// Remote MJPEG service.
    MJPEG,
    /// Remote MJPEG service requiring authentication.
    LockedMJPEG,
    /// General purpose TCP service.
    TCP,
}

impl ServiceType {
    /// Get code of the service type.
    pub fn code(self) -> u16 {
        match self {
            Self::ControlProtocol => SVC_TYPE_CONTROL_PROTOCOL,
            Self::RTSP => SVC_TYPE_RTSP,
            Self::LockedRTSP => SVC_TYPE_LOCKED_RTSP,
            Self::UnknownRTSP => SVC_TYPE_UNKNOWN_RTSP,
            Self::UnsupportedRTSP => SVC_TYPE_UNSUPPORTED_RTSP,
            Self::HTTP => SVC_TYPE_HTTP,
            Self::MJPEG => SVC_TYPE_MJPEG,
            Self::LockedMJPEG => SVC_TYPE_LOCKED_MJPEG,
            Self::TCP => SVC_TYPE_TCP,
        }
    }
}

/// Arrow service identifier.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct ServiceIdentifier {
    svc_type: ServiceType,
    mac: StableHashOption<MacAddr>,
    port: StableHashOption<u16>,
    path: StableHashOption<StableHashString>,
}

impl ServiceIdentifier {
    /// Check if this is the Control Protocol service  identifier.
    pub fn is_control(&self) -> bool {
        self.svc_type == ServiceType::ControlProtocol
    }
}

/// Arrow service.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Service {
    svc_type: ServiceType,
    mac: Option<MacAddr>,
    address: Option<SocketAddr>,
    path: Option<String>,
}

impl Service {
    /// Create a new Control Protocol service.
    #[doc(hidden)]
    pub fn control() -> Service {
        Self {
            svc_type: ServiceType::ControlProtocol,
            mac: None,
            address: None,
            path: None,
        }
    }

    /// Create a new RTSP service.
    pub fn rtsp(mac: MacAddr, address: SocketAddr, path: String) -> Self {
        Self {
            svc_type: ServiceType::RTSP,
            mac: Some(mac),
            address: Some(address),
            path: Some(path),
        }
    }

    /// Create a new Locked RTSP service.
    pub fn locked_rtsp(mac: MacAddr, address: SocketAddr, path: Option<String>) -> Self {
        Self {
            svc_type: ServiceType::LockedRTSP,
            mac: Some(mac),
            address: Some(address),
            path,
        }
    }

    /// Create a new Unknown RTSP service.
    pub fn unknown_rtsp(mac: MacAddr, address: SocketAddr) -> Self {
        Self {
            svc_type: ServiceType::UnknownRTSP,
            mac: Some(mac),
            address: Some(address),
            path: None,
        }
    }

    /// Create a new Unsupported RTSP service.
    pub fn unsupported_rtsp(mac: MacAddr, address: SocketAddr, path: String) -> Self {
        Self {
            svc_type: ServiceType::UnsupportedRTSP,
            mac: Some(mac),
            address: Some(address),
            path: Some(path),
        }
    }

    /// Create a new HTTP service.
    pub fn http(mac: MacAddr, address: SocketAddr) -> Self {
        Self {
            svc_type: ServiceType::HTTP,
            mac: Some(mac),
            address: Some(address),
            path: None,
        }
    }

    /// Create a new MJPEG service.
    pub fn mjpeg(mac: MacAddr, address: SocketAddr, path: String) -> Self {
        Self {
            svc_type: ServiceType::MJPEG,
            mac: Some(mac),
            address: Some(address),
            path: Some(path),
        }
    }

    /// Create a new Locked MJPEG service.
    pub fn locked_mjpeg(mac: MacAddr, address: SocketAddr, path: Option<String>) -> Self {
        Self {
            svc_type: ServiceType::LockedMJPEG,
            mac: Some(mac),
            address: Some(address),
            path,
        }
    }

    /// Create a new TCP service.
    pub fn tcp(mac: MacAddr, address: SocketAddr) -> Self {
        Self {
            svc_type: ServiceType::TCP,
            mac: Some(mac),
            address: Some(address),
            path: None,
        }
    }

    /// Check if this is the Control Protocol service.
    pub fn is_control(&self) -> bool {
        self.svc_type == ServiceType::ControlProtocol
    }

    /// Get service type.
    pub fn service_type(&self) -> ServiceType {
        self.svc_type
    }

    /// Get service MAC address.
    pub fn mac(&self) -> Option<MacAddr> {
        self.mac
    }

    /// Get service IP address and port.
    pub fn address(&self) -> Option<SocketAddr> {
        self.address
    }

    /// Get service IP address.
    pub fn ip_address(&self) -> Option<IpAddr> {
        self.address.map(|addr| addr.ip())
    }

    /// Get service port.
    pub fn port(&self) -> Option<u16> {
        self.address.map(|addr| addr.port())
    }

    /// Get service path.
    pub fn path(&self) -> Option<&str> {
        self.path.as_ref().map(|v| v as &str)
    }

    /// Convert service to service identifier.
    #[doc(hidden)]
    pub fn to_service_identifier(&self) -> ServiceIdentifier {
        ServiceIdentifier {
            svc_type: self.service_type(),
            mac: self.mac().into(),
            port: self.port().into(),
            path: self.path.clone().map(StableHashString::from).into(),
        }
    }
}

/// Custom option type with stable hash regardless of the system pointer width.
#[derive(Clone, Eq)]
enum StableHashOption<T> {
    None,
    Some(T),
}

impl<T> PartialEq for StableHashOption<T>
where
    T: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        if let Self::Some(a) = self {
            if let Self::Some(b) = other {
                a.eq(b)
            } else {
                false
            }
        } else {
            matches!(other, Self::None)
        }
    }
}

impl<T> Hash for StableHashOption<T>
where
    T: Hash,
{
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        if let Self::Some(v) = self {
            // write the discriminant value
            state.write_u32(1);

            // ... and hash the inner data
            v.hash(state);
        } else {
            state.write_u32(0);
        }
    }
}

impl<T> From<Option<T>> for StableHashOption<T> {
    fn from(val: Option<T>) -> Self {
        match val {
            Some(v) => Self::Some(v),
            None => Self::None,
        }
    }
}

/// String wrapper with stable hash regardless of the system pointer width.
///
/// Even though the default implementation for string hashing currently does
/// not hash the string length, there is an alternative implementation being
/// considered that would hash it.
///
/// Let's be careful here and fix the hash implementation.
#[derive(Clone, Eq)]
struct StableHashString {
    inner: String,
}

impl PartialEq for StableHashString {
    fn eq(&self, other: &Self) -> bool {
        self.inner.eq(&other.inner)
    }
}

impl Hash for StableHashString {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        state.write(self.inner.as_bytes());
        state.write_u8(0xff);
    }
}

impl From<String> for StableHashString {
    fn from(s: String) -> Self {
        Self { inner: s }
    }
}
