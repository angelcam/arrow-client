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
use openssl::x509::X509;

use crate::config::PersistentConfig;
use crate::context::ConnectionState;
use crate::storage::Storage;
use crate::utils::json::{FromJson, ToJson};

/// Type alias.
type SaveConfiguration = extern "C" fn(opaque: *mut c_void, configuration: *const c_char) -> c_int;

/// Type alias.
type LoadConfiguration =
    extern "C" fn(opaque: *mut c_void, configuration: *mut *mut c_char) -> c_int;

/// Type alias.
type FreeConfiguration = extern "C" fn(opaque: *mut c_void, configuration: *mut c_char);

/// Type alias.
type LoadCACertificates =
    extern "C" fn(opaque: *mut c_void, cert_storage: *mut SslConnectorBuilder) -> c_int;

/// Type alias.
type SaveConnectionState = extern "C" fn(opaque: *mut c_void, state: c_int) -> c_int;

/// Type alias.
type LoadPaths =
    extern "C" fn(opaque: *mut c_void, paths: *mut *mut *mut c_char, len: *mut size_t) -> c_int;

/// Type alias.
type FreePaths = extern "C" fn(opaque: *mut c_void, paths: *mut *mut c_char, len: size_t);

/// Storage based on native functions.
pub struct NativeStorage {
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

impl NativeStorage {
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

impl Storage for NativeStorage {
    fn save_configuration(&mut self, config: &PersistentConfig) -> Result<(), io::Error> {
        if let Some(func) = self.save_configuration {
            let mut data = Vec::new();

            config.to_json().write(&mut data)?;

            let res = func(self.opaque, data.as_ptr() as _);

            if res != 0 {
                return Err(io::Error::from_raw_os_error(res));
            }
        }

        Ok(())
    }

    fn load_configuration(&mut self) -> Result<PersistentConfig, io::Error> {
        if let Some(func) = self.load_configuration {
            let mut configuration = ptr::null_mut();

            let res = func(self.opaque, &mut configuration);

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
                free(self.opaque, configuration);
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

            let res = func(self.opaque, s);

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
            let res = func(self.opaque, ssl_connector_builder);

            if res != 0 {
                return Err(io::Error::from_raw_os_error(res as _));
            }
        }

        Ok(())
    }
}

unsafe impl Send for NativeStorage {}

/// Helper function for loading paths.
fn load_paths(
    opaque: *mut c_void,
    load: LoadPaths,
    free: Option<FreePaths>,
) -> Result<Vec<String>, io::Error> {
    let mut paths_ptr = ptr::null_mut();
    let mut len = 0;

    let res = load(opaque, &mut paths_ptr, &mut len);

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
        free(opaque, paths_ptr, len);
    }

    let mut paths = Vec::with_capacity(res.len());

    for path in res {
        paths.push(path?);
    }

    Ok(paths)
}

/// Create a new storage.
#[no_mangle]
pub extern "C" fn ac__storage__new(opaque: *mut c_void) -> *mut NativeStorage {
    Box::into_raw(Box::new(NativeStorage::new(opaque)))
}

/// Free the storage.
#[no_mangle]
pub extern "C" fn ac__storage__free(storage: *mut NativeStorage) {
    unsafe { Box::from_raw(storage) };
}

/// Set function for saving client configuration.
#[no_mangle]
pub extern "C" fn ac__storage__set_save_configuration_func(
    storage: *mut NativeStorage,
    func: SaveConfiguration,
) {
    let storage = unsafe { &mut *storage };

    storage.save_configuration = Some(func);
}

/// Set function for loading client configuration.
#[no_mangle]
pub extern "C" fn ac__storage__set_load_configuration_func(
    storage: *mut NativeStorage,
    load: LoadConfiguration,
    free: Option<FreeConfiguration>,
) {
    let storage = unsafe { &mut *storage };

    storage.load_configuration = Some(load);
    storage.free_configuration = free;
}

/// Set function for saving client connection state.
#[no_mangle]
pub extern "C" fn ac__storage__set_save_connection_state_func(
    storage: *mut NativeStorage,
    func: SaveConnectionState,
) {
    let storage = unsafe { &mut *storage };

    storage.save_connection_state = Some(func);
}

/// Set function for loading RTSP paths.
#[no_mangle]
pub extern "C" fn ac__storage__set_load_rtsp_paths_func(
    storage: *mut NativeStorage,
    load: LoadPaths,
    free: Option<FreePaths>,
) {
    let storage = unsafe { &mut *storage };

    storage.load_rtsp_paths = Some(load);
    storage.free_rtsp_paths = free;
}

/// Set function for loading MJPEG paths.
#[no_mangle]
pub extern "C" fn ac__storage__set_load_mjpeg_paths_func(
    storage: *mut NativeStorage,
    load: LoadPaths,
    free: Option<FreePaths>,
) {
    let storage = unsafe { &mut *storage };

    storage.load_mjpeg_paths = Some(load);
    storage.free_mjpeg_paths = free;
}

/// Set function for loading CA certificates.
#[no_mangle]
pub extern "C" fn ac__storage__set_load_ca_certificates_func(
    storage: *mut NativeStorage,
    func: LoadCACertificates,
) {
    let storage = unsafe { &mut *storage };

    storage.load_ca_certificates = Some(func);
}

/// Load a given CA certificate file.
#[no_mangle]
pub extern "C" fn ac__ca_cert_storage__load_ca_file(
    cert_storage: *mut SslConnectorBuilder,
    file: *const c_char,
) -> c_int {
    let cert_storage = unsafe { &mut *cert_storage };
    let file_cstr = unsafe { CStr::from_ptr(file as _) };

    if let Ok(file) = file_cstr.to_str() {
        cert_storage
            .set_ca_file(file)
            .map(|_| 0)
            .unwrap_or(libc::EINVAL)
    } else {
        libc::EINVAL
    }
}

/// Load a given PEM certificate.
#[no_mangle]
pub extern "C" fn ac__ca_cert_storage__load_pem(
    cert_storage: *mut SslConnectorBuilder,
    pem: *const u8,
    size: size_t,
) -> c_int {
    let cert_storage = unsafe { &mut *cert_storage };
    let data = unsafe { slice::from_raw_parts(pem, size as _) };

    if let Ok(cert) = X509::from_pem(data) {
        cert_storage
            .add_client_ca(&cert)
            .map(|_| 0)
            .unwrap_or(libc::EINVAL)
    } else {
        libc::EINVAL
    }
}

/// Load a given DER certificate.
#[no_mangle]
pub extern "C" fn ac__ca_cert_storage__load_der(
    cert_storage: *mut SslConnectorBuilder,
    der: *const u8,
    size: size_t,
) -> c_int {
    let cert_storage = unsafe { &mut *cert_storage };
    let data = unsafe { slice::from_raw_parts(der, size as _) };

    if let Ok(cert) = X509::from_der(data) {
        cert_storage
            .add_client_ca(&cert)
            .map(|_| 0)
            .unwrap_or(libc::EINVAL)
    } else {
        libc::EINVAL
    }
}
