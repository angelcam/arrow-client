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

use std::io;
use std::ptr;
use std::slice;

use std::ffi::CStr;

use libc::{c_char, c_int, c_void, size_t};

use openssl::ssl::SslConnectorBuilder;

use crate::config::PersistentConfig;
use crate::context::ConnectionState;
use crate::exports::storage::DynStorage;
use crate::storage::Storage;
use crate::utils::json::{FromJson, ToJson};

/// Type alias.
type SaveConfiguration =
    unsafe extern "C" fn(opaque: *mut c_void, configuration: *const c_char) -> c_int;

/// Type alias.
type LoadConfiguration =
    unsafe extern "C" fn(opaque: *mut c_void, configuration: *mut *mut c_char) -> c_int;

/// Type alias.
type FreeConfiguration = unsafe extern "C" fn(opaque: *mut c_void, configuration: *mut c_char);

/// Type alias.
type LoadCACertificates =
    unsafe extern "C" fn(opaque: *mut c_void, cert_storage: *mut SslConnectorBuilder) -> c_int;

/// Type alias.
type SaveConnectionState = unsafe extern "C" fn(opaque: *mut c_void, state: c_int) -> c_int;

/// Type alias.
type LoadPaths = unsafe extern "C" fn(
    opaque: *mut c_void,
    paths: *mut *mut *mut c_char,
    len: *mut size_t,
) -> c_int;

/// Type alias.
type FreePaths = unsafe extern "C" fn(opaque: *mut c_void, paths: *mut *mut c_char, len: size_t);

/// Custom storage based on native functions.
pub struct CustomStorage {
    opaque: *mut c_void,
    save_configuration: Option<SaveConfiguration>,
    load_configuration: Option<LoadConfiguration>,
    free_configuration: Option<FreeConfiguration>,
    load_ca_certificates: Option<LoadCACertificates>,
    save_connection_state: Option<SaveConnectionState>,
    load_rtsp_paths: Option<LoadPaths>,
    free_rtsp_paths: Option<FreePaths>,
    load_mjpeg_paths: Option<LoadPaths>,
    free_mjpeg_paths: Option<FreePaths>,
}

impl CustomStorage {
    /// Create a new native storage.
    fn new(opaque: *mut c_void) -> Self {
        Self {
            opaque,
            save_configuration: None,
            load_configuration: None,
            free_configuration: None,
            load_ca_certificates: None,
            save_connection_state: None,
            load_rtsp_paths: None,
            free_rtsp_paths: None,
            load_mjpeg_paths: None,
            free_mjpeg_paths: None,
        }
    }
}

impl Storage for CustomStorage {
    fn save_configuration(&mut self, config: &PersistentConfig) -> Result<(), io::Error> {
        if let Some(func) = self.save_configuration {
            let mut data = Vec::new();

            config.to_json().write(&mut data)?;

            let res = unsafe { func(self.opaque, data.as_ptr() as _) };

            if res != 0 {
                return Err(io::Error::from_raw_os_error(res));
            }
        }

        Ok(())
    }

    fn load_configuration(&mut self) -> Result<PersistentConfig, io::Error> {
        if let Some(func) = self.load_configuration {
            let mut configuration = ptr::null_mut();

            let res = unsafe { func(self.opaque, &mut configuration) };

            if res != 0 {
                return Err(io::Error::from_raw_os_error(res));
            } else if configuration.is_null() {
                return self.create_configuration();
            }

            let dptr = unsafe { CStr::from_ptr(configuration as _) };
            let data = dptr.to_str().map(|v| v.to_string()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::Other,
                    "configuration is not an UTF-8 encoded string",
                )
            });

            if let Some(free) = self.free_configuration {
                unsafe { free(self.opaque, configuration) };
            }

            let object = json::parse(&data?).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("unable to parse configuration: {}", err),
                )
            })?;

            let config = PersistentConfig::from_json(object)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;

            Ok(config)
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "missing load function",
            ))
        }
    }

    fn save_connection_state(&mut self, state: ConnectionState) -> Result<(), io::Error> {
        if let Some(func) = self.save_connection_state {
            let s = match state {
                ConnectionState::Disconnected => 0,
                ConnectionState::Connected => 1,
                ConnectionState::Unauthorized => 2,
            };

            let res = unsafe { func(self.opaque, s) };

            if res != 0 {
                return Err(io::Error::from_raw_os_error(res));
            }
        }

        Ok(())
    }

    fn load_rtsp_paths(&mut self) -> Result<Vec<String>, io::Error> {
        if let Some(load) = self.load_rtsp_paths {
            load_paths(self.opaque, load, self.free_rtsp_paths)
        } else {
            Ok(Vec::new())
        }
    }

    fn load_mjpeg_paths(&mut self) -> Result<Vec<String>, io::Error> {
        if let Some(load) = self.load_mjpeg_paths {
            load_paths(self.opaque, load, self.free_mjpeg_paths)
        } else {
            Ok(Vec::new())
        }
    }

    fn load_ca_certificates(
        &mut self,
        ssl_connector_builder: &mut SslConnectorBuilder,
    ) -> Result<(), io::Error> {
        if let Some(func) = self.load_ca_certificates {
            let res = unsafe { func(self.opaque, ssl_connector_builder) };

            if res != 0 {
                return Err(io::Error::from_raw_os_error(res as _));
            }
        }

        Ok(())
    }
}

unsafe impl Send for CustomStorage {}

/// Helper function for loading paths.
fn load_paths(
    opaque: *mut c_void,
    load: LoadPaths,
    free: Option<FreePaths>,
) -> Result<Vec<String>, io::Error> {
    let mut paths_ptr = ptr::null_mut();
    let mut len = 0;

    let res = unsafe { load(opaque, &mut paths_ptr, &mut len) };

    if res != 0 {
        return Err(io::Error::from_raw_os_error(res as _));
    }

    let paths = unsafe { slice::from_raw_parts(paths_ptr, len) };

    let mut res = Vec::with_capacity(len);

    for path in paths {
        let path = unsafe { CStr::from_ptr(*path as _) };
        let path = path.to_str().map(|v| v.to_string()).map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "path is not an UTF-8 encoded string")
        });

        res.push(path);
    }

    if let Some(free) = free {
        unsafe { free(opaque, paths_ptr, len) };
    }

    let mut paths = Vec::with_capacity(res.len());

    for path in res {
        paths.push(path?);
    }

    Ok(paths)
}

/// Create a new custom storage builder.
#[no_mangle]
pub unsafe extern "C" fn ac__custom_storage_builder__new(
    opaque: *mut c_void,
) -> *mut CustomStorage {
    Box::into_raw(Box::new(CustomStorage::new(opaque)))
}

/// Free the storage builder.
#[no_mangle]
pub unsafe extern "C" fn ac__custom_storage_builder__free(builder: *mut CustomStorage) {
    Box::from_raw(builder);
}

/// Set function for saving client configuration.
#[no_mangle]
pub unsafe extern "C" fn ac__custom_storage_builder__set_save_configuration_func(
    builder: *mut CustomStorage,
    func: SaveConfiguration,
) {
    let storage = &mut *builder;

    storage.save_configuration = Some(func);
}

/// Set function for loading client configuration.
#[no_mangle]
pub unsafe extern "C" fn ac__custom_storage_builder__set_load_configuration_func(
    builder: *mut CustomStorage,
    load: LoadConfiguration,
    free: Option<FreeConfiguration>,
) {
    let storage = &mut *builder;

    storage.load_configuration = Some(load);
    storage.free_configuration = free;
}

/// Set function for saving client connection state.
#[no_mangle]
pub unsafe extern "C" fn ac__custom_storage_builder__set_save_connection_state_func(
    builder: *mut CustomStorage,
    func: SaveConnectionState,
) {
    let storage = &mut *builder;

    storage.save_connection_state = Some(func);
}

/// Set function for loading RTSP paths.
#[no_mangle]
pub unsafe extern "C" fn ac__custom_storage_builder__set_load_rtsp_paths_func(
    builder: *mut CustomStorage,
    load: LoadPaths,
    free: Option<FreePaths>,
) {
    let storage = &mut *builder;

    storage.load_rtsp_paths = Some(load);
    storage.free_rtsp_paths = free;
}

/// Set function for loading MJPEG paths.
#[no_mangle]
pub unsafe extern "C" fn ac__custom_storage_builder__set_load_mjpeg_paths_func(
    builder: *mut CustomStorage,
    load: LoadPaths,
    free: Option<FreePaths>,
) {
    let storage = &mut *builder;

    storage.load_mjpeg_paths = Some(load);
    storage.free_mjpeg_paths = free;
}

/// Set function for loading CA certificates.
#[no_mangle]
pub unsafe extern "C" fn ac__custom_storage_builder__set_load_ca_certificates_func(
    builder: *mut CustomStorage,
    func: LoadCACertificates,
) {
    let storage = &mut *builder;

    storage.load_ca_certificates = Some(func);
}

/// Build the storage.
#[no_mangle]
pub unsafe extern "C" fn ac__custom_storage_builder__build(
    builder: *mut CustomStorage,
) -> *mut DynStorage {
    let builder = Box::from_raw(builder);

    Box::into_raw(Box::new(*builder))
}
