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
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::sync::Mutex;

use crate::net::raw::devices::EthernetDevice;

/// Network interfaces cache.
pub struct NetworkInterfacesCache {
    interfaces: Mutex<Option<CachedNetworkInterfaces>>,
}

impl NetworkInterfacesCache {
    /// Create a new cache.
    pub fn new() -> Self {
        Self {
            interfaces: Mutex::new(None),
        }
    }

    /// Get the cached list of network interfaces and refresh the cache if
    /// needed.
    pub async fn get_interfaces(&self) -> Arc<Vec<EthernetDevice>> {
        let mut inner = self.interfaces.lock().await;

        if let Some(cached) = inner.as_ref()
            && cached.timestamp.elapsed() < Duration::from_secs(10)
        {
            return cached.interfaces.clone();
        }

        let fresh = EthernetDevice::list().await;

        let interfaces = Arc::new(fresh);

        *inner = Some(CachedNetworkInterfaces::from(interfaces.clone()));

        interfaces
    }
}

/// Cached network interfaces.
struct CachedNetworkInterfaces {
    interfaces: Arc<Vec<EthernetDevice>>,
    timestamp: Instant,
}

impl From<Arc<Vec<EthernetDevice>>> for CachedNetworkInterfaces {
    fn from(interfaces: Arc<Vec<EthernetDevice>>) -> Self {
        Self {
            interfaces,
            timestamp: Instant::now(),
        }
    }
}
