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

use std::ptr;

use libc::c_char;

use crate::exports::storage::DynStorage;
use crate::storage::{DefaultStorage, DefaultStorageBuilder};
use crate::utils::logger::BoxLogger;

use crate::exports::cstr_to_str;
use crate::exports::optional_cstr_to_str;

/// Create a new builder for the default storage.
///
/// # Arguments
/// * `config_file` - path to configuration file
/// * `lock_file` - path to lock file, may be NULL
#[no_mangle]
pub unsafe extern "C" fn ac__default_storage_builder__new(
    config_file: *const c_char,
    lock_file: *const c_char,
) -> *mut DefaultStorageBuilder {
    let config_file = cstr_to_str(config_file);
    let lock_file = optional_cstr_to_str(lock_file);

    if let Ok(builder) = DefaultStorage::builder(config_file, lock_file) {
        Box::into_raw(Box::new(builder))
    } else {
        ptr::null_mut()
    }
}

/// Free the default storage builder.
#[no_mangle]
pub unsafe extern "C" fn ac__default_storage_builder__free(builder: *mut DefaultStorageBuilder) {
    Box::from_raw(builder);
}

/// Set path for the configuration skeleton file.
#[no_mangle]
pub unsafe extern "C" fn ac__default_storage_builder__set_config_skeleton_file(
    builder: *mut DefaultStorageBuilder,
    file: *const c_char,
) {
    (&mut *builder).config_skeleton_file(optional_cstr_to_str(file));
}

/// Set path for the connection state file.
#[no_mangle]
pub unsafe extern "C" fn ac__default_storage_builder__set_connection_state_file(
    builder: *mut DefaultStorageBuilder,
    file: *const c_char,
) {
    (&mut *builder).connection_state_file(optional_cstr_to_str(file));
}

/// Set path for the identity file.
#[no_mangle]
pub unsafe extern "C" fn ac__default_storage_builder__set_identity_file(
    builder: *mut DefaultStorageBuilder,
    file: *const c_char,
) {
    (&mut *builder).identity_file(optional_cstr_to_str(file));
}

/// Set path for the file containing RTSP paths.
#[no_mangle]
pub unsafe extern "C" fn ac__default_storage_builder__set_rtsp_paths_file(
    builder: *mut DefaultStorageBuilder,
    file: *const c_char,
) {
    (&mut *builder).rtsp_paths_file(optional_cstr_to_str(file));
}

/// Set path for the file containing MJPEG paths.
#[no_mangle]
pub unsafe extern "C" fn ac__default_storage_builder__set_mjpeg_paths_file(
    builder: *mut DefaultStorageBuilder,
    file: *const c_char,
) {
    (&mut *builder).mjpeg_paths_file(optional_cstr_to_str(file));
}

/// Add a path to a CA certificate.
#[no_mangle]
pub unsafe extern "C" fn ac__default_storage_builder__add_ca_cerificate(
    builder: *mut DefaultStorageBuilder,
    file: *const c_char,
) {
    (&mut *builder).add_ca_cerificate(cstr_to_str(file));
}

/// Set logger.
#[no_mangle]
pub unsafe extern "C" fn ac__default_storage_builder__set_logger(
    builder: *mut DefaultStorageBuilder,
    logger: *mut BoxLogger,
) {
    let logger = Box::from_raw(logger);

    (&mut *builder).logger(*logger);
}

/// Build the storage. The function takes ownership of the builder.
#[no_mangle]
pub unsafe extern "C" fn ac__default_storage_builder__build(
    builder: *mut DefaultStorageBuilder,
) -> *mut DynStorage {
    let builder = Box::from_raw(builder);

    Box::into_raw(Box::new(builder.build()))
}
