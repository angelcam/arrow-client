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
pub mod storage;

use std::ptr;
use std::thread;

use std::ffi::CStr;
use std::thread::JoinHandle;

use libc::c_char;

use crate::runtime;

use crate::client::{ArrowClient, ArrowClientTask};
use crate::config::ConfigBuilder;
use crate::exports::storage::NativeStorage;

/// Helper struct.
pub struct NativeArrowClient {
    client: ArrowClient,
    task: Option<ArrowClientTask>,
}

/// Create a new Arrow client from a given config. The function takes ownership
/// of the config and the storage.
#[no_mangle]
pub extern "C" fn ac__arrow_client__new(
    builder: *mut ConfigBuilder,
    storage: *mut NativeStorage,
    arrow_service_address: *const c_char,
) -> *mut NativeArrowClient {
    let builder = unsafe { Box::from_raw(builder) };
    let storage = unsafe { Box::from_raw(storage) };
    let arrow_service_address = unsafe { CStr::from_ptr(arrow_service_address as _) };

    if let Ok(addr) = arrow_service_address.to_str() {
        if let Ok(config) = (*builder).build(*storage, addr) {
            let (client, task) = ArrowClient::new(config);

            let res = NativeArrowClient {
                client,
                task: Some(task),
            };

            return Box::into_raw(Box::new(res));
        }
    }

    ptr::null_mut()
}

/// Free (and close) a given Arrow client.
#[no_mangle]
pub extern "C" fn ac__arrow_client__free(client: *mut NativeArrowClient) {
    unsafe { Box::from_raw(client) };
}

/// Start a given Arrow client in the background and return a join handle. The
/// function does nothing if the client has been already started. The returned
/// join handle must be either freed or awaited.
#[no_mangle]
pub extern "C" fn ac__arrow_client__start(client: *mut NativeArrowClient) -> *mut JoinHandle<()> {
    let client = unsafe { &mut *client };

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
pub extern "C" fn ac__arrow_client__start_blocking(client: *mut NativeArrowClient) {
    let client = unsafe { &mut *client };

    if let Some(task) = client.task.take() {
        runtime::run(task)
    }
}

/// Close a given Arrow client.
#[no_mangle]
pub extern "C" fn ac__arrow_client__close(client: *mut NativeArrowClient) {
    let client = unsafe { &mut *client };

    client.client.close();
}

/// Free a given Arrow client join handle.
#[no_mangle]
pub extern "C" fn ac__arrow_client_join_handle__free(handle: *mut JoinHandle<()>) {
    unsafe { Box::from_raw(handle) };
}

/// Await a given Arrow client join handle.
#[no_mangle]
pub extern "C" fn ac__arrow_client_join_handle__join(handle: *mut JoinHandle<()>) {
    let handle = unsafe { Box::from_raw(handle) };

    (*handle).join().unwrap_or_default()
}
