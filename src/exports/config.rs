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

use std::slice;

use libc::c_int;

use crate::config::{Config, ConfigBuilder};
use crate::net::raw::ether::MacAddr;
use crate::utils::logger::BoxLogger;

/// Create a new Arrow client config.
#[no_mangle]
pub unsafe extern "C" fn ac__config__new() -> *mut ConfigBuilder {
    Box::into_raw(Box::new(Config::builder()))
}

/// Free the config.
#[no_mangle]
pub unsafe extern "C" fn ac__config__free(config: *mut ConfigBuilder) {
    Box::from_raw(config);
}

/// Set logger. The function takes ownership of a given logger.
#[no_mangle]
pub unsafe extern "C" fn ac__config__set_logger(
    config: *mut ConfigBuilder,
    logger: *mut BoxLogger,
) {
    let logger = Box::from_raw(logger);

    (&mut *config).logger(*logger);
}

/// Set MAC address. The `mac_address` parameter is expected to be a an array
/// of six bytes or NULL.
#[no_mangle]
pub unsafe extern "C" fn ac__config__set_mac_address(
    config: *mut ConfigBuilder,
    mac_address: *const u8,
) {
    let mac_address = if mac_address.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(mac_address, 6))
    };

    let mac_address = mac_address.map(MacAddr::from_slice);

    (&mut *config).mac_address(mac_address);
}

/// Enable/disable diagnostic mode.
#[no_mangle]
pub unsafe extern "C" fn ac__config__set_diagnostic_mode(
    config: *mut ConfigBuilder,
    enabled: c_int,
) {
    (&mut *config).diagnostic_mode(enabled != 0);
}

/// Enable/disable automatic service discovery.
#[no_mangle]
pub unsafe extern "C" fn ac__config__set_discovery(config: *mut ConfigBuilder, enabled: c_int) {
    (&mut *config).discovery(enabled != 0);
}

/// Enable/disable verbose mode.
#[no_mangle]
pub unsafe extern "C" fn ac__config__set_verbose(config: *mut ConfigBuilder, enabled: c_int) {
    (&mut *config).verbose(enabled != 0);
}
