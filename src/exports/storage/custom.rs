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

use std::io;
use std::ptr;
use std::slice;

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

use openssl::ssl::SslConnectorBuilder;

use crate::config::PersistentConfig;
use crate::context::ConnectionState;
use crate::exports::storage::DynStorage;
use crate::storage::Storage;
use crate::utils::json::{FromJson, ToJson};

use crate::exports::connection_state_to_c_int;
use crate::exports::mem::ac__free;

/// Type alias.
type SaveConfiguration =
    unsafe extern "C" fn(opaque: *mut c_void, configuration: *const c_char) -> c_int;

/// Type alias.
type LoadConfiguration =
    unsafe extern "C" fn(opaque: *mut c_void, configuration: *mut *mut c_char) -> c_int;

/// Type alias.
#[allow(clippy::upper_case_acronyms)]
type LoadCACertificates =
    unsafe extern "C" fn(opaque: *mut c_void, cert_storage: *mut SslConnectorBuilder) -> c_int;

/// Type alias.
type SaveConnectionState = unsafe extern "C" fn(opaque: *mut c_void, state: c_int) -> c_int;

/// Type alias.
type LoadPaths = unsafe extern "C" fn(
    opaque: *mut c_void,
    paths: *mut *mut *mut c_char,
    len: *mut usize,
) -> c_int;

/// Custom storage based on native functions.
pub struct CustomStorage {
    opaque: *mut c_void,
    save_configuration: Option<SaveConfiguration>,
    load_configuration: Option<LoadConfiguration>,
    load_ca_certificates: Option<LoadCACertificates>,
    save_connection_state: Option<SaveConnectionState>,
    load_rtsp_paths: Option<LoadPaths>,
    load_mjpeg_paths: Option<LoadPaths>,
}

impl CustomStorage {
    /// Create a new native storage.
    fn new(opaque: *mut c_void) -> Self {
        Self {
            opaque,
            save_configuration: None,
            load_configuration: None,
            load_ca_certificates: None,
            save_connection_state: None,
            load_rtsp_paths: None,
            load_mjpeg_paths: None,
        }
    }
}

impl Storage for CustomStorage {
    fn save_configuration(&mut self, config: &PersistentConfig) -> Result<(), io::Error> {
        if let Some(func) = self.save_configuration {
            let mut data = Vec::new();

            config.to_json().write(&mut data)?;

            let data = CString::new(data).unwrap();

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

            let data = unsafe { CStr::from_ptr(configuration as _) };

            let config = data
                .to_str()
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        "configuration is not an UTF-8 encoded string",
                    )
                })
                .and_then(|data| {
                    json::parse(data).map_err(|err| {
                        io::Error::new(
                            io::ErrorKind::Other,
                            format!("unable to parse configuration: {}", err),
                        )
                    })
                })
                .and_then(|object| {
                    PersistentConfig::from_json(object)
                        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
                });

            unsafe { ac__free(configuration as _) };

            config
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "missing load function",
            ))
        }
    }

    fn save_connection_state(&mut self, state: ConnectionState) -> Result<(), io::Error> {
        if let Some(func) = self.save_connection_state {
            let res = unsafe { func(self.opaque, connection_state_to_c_int(state)) };

            if res != 0 {
                return Err(io::Error::from_raw_os_error(res));
            }
        }

        Ok(())
    }

    fn load_rtsp_paths(&mut self) -> Result<Vec<String>, io::Error> {
        if let Some(load) = self.load_rtsp_paths {
            unsafe { load_paths(self.opaque, load) }
        } else {
            Ok(Vec::new())
        }
    }

    fn load_mjpeg_paths(&mut self) -> Result<Vec<String>, io::Error> {
        if let Some(load) = self.load_mjpeg_paths {
            unsafe { load_paths(self.opaque, load) }
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
unsafe fn load_paths(opaque: *mut c_void, load: LoadPaths) -> Result<Vec<String>, io::Error> {
    let mut paths_ptr = ptr::null_mut();
    let mut len = 0;

    let res = load(opaque, &mut paths_ptr, &mut len);

    if res != 0 {
        return Err(io::Error::from_raw_os_error(res as _));
    }

    let mut paths = Vec::with_capacity(len);

    for path_ptr in slice::from_raw_parts(paths_ptr, len) {
        let path = CStr::from_ptr(*path_ptr as _);
        let path = path.to_str().map(|v| v.to_string()).map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "path is not an UTF-8 encoded string")
        });

        ac__free(*path_ptr as _);

        paths.push(path);
    }

    ac__free(paths_ptr as _);

    let mut res = Vec::with_capacity(paths.len());

    for path in paths {
        res.push(path?);
    }

    Ok(res)
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
    (*builder).save_configuration = Some(func);
}

/// Set function for loading client configuration. The function must allocate
/// the configuration using `ac__malloc()`.
#[no_mangle]
pub unsafe extern "C" fn ac__custom_storage_builder__set_load_configuration_func(
    builder: *mut CustomStorage,
    load: LoadConfiguration,
) {
    (*builder).load_configuration = Some(load);
}

/// Set function for saving client connection state.
#[no_mangle]
pub unsafe extern "C" fn ac__custom_storage_builder__set_save_connection_state_func(
    builder: *mut CustomStorage,
    func: SaveConnectionState,
) {
    (*builder).save_connection_state = Some(func);
}

/// Set function for loading RTSP paths. The function must allocate the paths
/// using `ac__malloc()`.
#[no_mangle]
pub unsafe extern "C" fn ac__custom_storage_builder__set_load_rtsp_paths_func(
    builder: *mut CustomStorage,
    load: LoadPaths,
) {
    (*builder).load_rtsp_paths = Some(load);
}

/// Set function for loading MJPEG paths. The function must allocate the paths
/// using `ac__malloc()`.
#[no_mangle]
pub unsafe extern "C" fn ac__custom_storage_builder__set_load_mjpeg_paths_func(
    builder: *mut CustomStorage,
    load: LoadPaths,
) {
    (*builder).load_mjpeg_paths = Some(load);
}

/// Set function for loading CA certificates.
#[no_mangle]
pub unsafe extern "C" fn ac__custom_storage_builder__set_load_ca_certificates_func(
    builder: *mut CustomStorage,
    func: LoadCACertificates,
) {
    (*builder).load_ca_certificates = Some(func);
}

/// Build the storage.
#[no_mangle]
pub unsafe extern "C" fn ac__custom_storage_builder__build(
    builder: *mut CustomStorage,
) -> *mut DynStorage {
    let builder = Box::from_raw(builder);
    let storage = DynStorage::new(*builder);

    Box::into_raw(Box::new(storage))
}
