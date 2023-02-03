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

use std::os::raw::{c_char, c_int};

use openssl::ssl::SslConnectorBuilder;
use openssl::x509::X509;

use crate::exports::cstr_to_str;

/// Load a given CA certificate file.
#[no_mangle]
pub unsafe extern "C" fn ac__ca_cert_storage__load_ca_file(
    cert_storage: *mut SslConnectorBuilder,
    file: *const c_char,
) -> c_int {
    (*cert_storage)
        .set_ca_file(cstr_to_str(file))
        .map(|_| 0)
        .unwrap_or(libc::EINVAL)
}

/// Load a given PEM certificate.
#[no_mangle]
pub unsafe extern "C" fn ac__ca_cert_storage__load_pem(
    cert_storage: *mut SslConnectorBuilder,
    pem: *const u8,
    size: usize,
) -> c_int {
    if let Ok(cert) = X509::from_pem(slice::from_raw_parts(pem, size as _)) {
        (*cert_storage)
            .add_client_ca(&cert)
            .map(|_| 0)
            .unwrap_or(libc::EINVAL)
    } else {
        libc::EINVAL
    }
}

/// Load a given DER certificate.
#[no_mangle]
pub unsafe extern "C" fn ac__ca_cert_storage__load_der(
    cert_storage: *mut SslConnectorBuilder,
    der: *const u8,
    size: usize,
) -> c_int {
    if let Ok(cert) = X509::from_der(slice::from_raw_parts(der, size as _)) {
        (*cert_storage)
            .add_client_ca(&cert)
            .map(|_| 0)
            .unwrap_or(libc::EINVAL)
    } else {
        libc::EINVAL
    }
}
