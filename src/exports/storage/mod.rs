// Copyright 2019 Angelcam, Inc.
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

#![allow(clippy::missing_safety_doc)]

pub mod ca;
pub mod custom;
pub mod default;

use std::io::Error;

use openssl::ssl::SslConnectorBuilder;

use crate::config::PersistentConfig;
use crate::context::ConnectionState;
use crate::storage::Storage;

/// Helper struct.
pub struct DynStorage {
    inner: Box<dyn Storage + Send>,
}

impl DynStorage {
    /// Create a new abstract storage.
    pub fn new<T>(storage: T) -> Self
    where
        T: 'static + Storage + Send,
    {
        Self {
            inner: Box::new(storage),
        }
    }
}

impl Storage for DynStorage {
    fn save_configuration(&mut self, config: &PersistentConfig) -> Result<(), Error> {
        self.inner.save_configuration(config)
    }

    fn create_configuration(&mut self) -> Result<PersistentConfig, Error> {
        self.inner.create_configuration()
    }

    fn load_configuration(&mut self) -> Result<PersistentConfig, Error> {
        self.inner.load_configuration()
    }

    fn save_connection_state(&mut self, state: ConnectionState) -> Result<(), Error> {
        self.inner.save_connection_state(state)
    }

    fn load_rtsp_paths(&mut self) -> Result<Vec<String>, Error> {
        self.inner.load_rtsp_paths()
    }

    fn load_mjpeg_paths(&mut self) -> Result<Vec<String>, Error> {
        self.inner.load_mjpeg_paths()
    }

    fn load_ca_certificates(
        &mut self,
        ssl_connector_builder: &mut SslConnectorBuilder,
    ) -> Result<(), Error> {
        self.inner.load_ca_certificates(ssl_connector_builder)
    }
}

/// Free a given storage.
#[no_mangle]
pub unsafe extern "C" fn ac__storage__free(storage: *mut DynStorage) {
    let _ = Box::from_raw(storage);
}
