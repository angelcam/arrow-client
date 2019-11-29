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

pub mod config;
pub mod logger;
pub mod storage;

use std::ptr;
use std::str;
use std::thread;

use std::ffi::CStr;
use std::thread::JoinHandle;

use libc::c_char;

use crate::runtime;

use crate::client::{ArrowClient, ArrowClientTask};
use crate::config::ConfigBuilder;
use crate::exports::storage::DynStorage;

/// Helper function.
unsafe fn optional_cstr_to_str<'a>(s: *const c_char) -> Option<&'a str> {
    if s.is_null() {
        return None;
    }

    let s = CStr::from_ptr(s);

    Some(str::from_utf8_unchecked(s.to_bytes()))
}

/// Helper function.
unsafe fn cstr_to_str<'a>(s: *const c_char) -> &'a str {
    let s = CStr::from_ptr(s);

    str::from_utf8_unchecked(s.to_bytes())
}

/// Helper struct.
pub struct NativeArrowClient {
    client: ArrowClient,
    task: Option<ArrowClientTask>,
}

/// Create a new Arrow client from a given config. The function takes ownership
/// of the config and the storage.
#[no_mangle]
pub unsafe extern "C" fn ac__arrow_client__new(
    builder: *mut ConfigBuilder,
    storage: *mut DynStorage,
    arrow_service_address: *const c_char,
) -> *mut NativeArrowClient {
    let builder = Box::from_raw(builder);
    let storage = Box::from_raw(storage);
    let arrow_service_address = cstr_to_str(arrow_service_address);

    if let Ok(config) = builder.build(storage, arrow_service_address) {
        let (client, task) = ArrowClient::new(config);

        let res = NativeArrowClient {
            client,
            task: Some(task),
        };

        Box::into_raw(Box::new(res))
    } else {
        ptr::null_mut()
    }
}

/// Free (and close) a given Arrow client.
#[no_mangle]
pub unsafe extern "C" fn ac__arrow_client__free(client: *mut NativeArrowClient) {
    Box::from_raw(client);
}

/// Start a given Arrow client in the background and return a join handle. The
/// function does nothing if the client has been already started. The returned
/// join handle must be either freed or awaited.
#[no_mangle]
pub unsafe extern "C" fn ac__arrow_client__start(
    client: *mut NativeArrowClient,
) -> *mut JoinHandle<()> {
    let client = &mut *client;

    if let Some(task) = client.task.take() {
        let handle = thread::spawn(move || runtime::run(task));

        Box::into_raw(Box::new(handle))
    } else {
        ptr::null_mut()
    }
}

/// Start a given Arrow client blocking the current thread. The function does
/// nothing if the client has been already started.
#[no_mangle]
pub unsafe extern "C" fn ac__arrow_client__start_blocking(client: *mut NativeArrowClient) {
    let client = &mut *client;

    if let Some(task) = client.task.take() {
        runtime::run(task)
    }
}

/// Close a given Arrow client.
#[no_mangle]
pub unsafe extern "C" fn ac__arrow_client__close(client: *mut NativeArrowClient) {
    (&mut *client).client.close();
}

/// Free a given join handle.
#[no_mangle]
pub unsafe extern "C" fn ac__join_handle__free(handle: *mut JoinHandle<()>) {
    Box::from_raw(handle);
}

/// Await a given join handle.
#[no_mangle]
pub unsafe extern "C" fn ac__join_handle__join(handle: *mut JoinHandle<()>) {
    let handle = Box::from_raw(handle);

    handle.join().unwrap_or_default()
}
