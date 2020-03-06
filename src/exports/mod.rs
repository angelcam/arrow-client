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

pub mod config;
pub mod logger;
pub mod mem;
pub mod storage;
pub mod svc_table;

use std::ptr;
use std::slice;
use std::str;
use std::thread;

use std::ffi::CStr;
use std::thread::JoinHandle;

use libc::{c_char, c_int, c_void};

use crate::runtime;

use crate::client::{ArrowClient, ArrowClientTask};
use crate::config::ConfigBuilder;
use crate::exports::storage::DynStorage;
use crate::exports::svc_table::NativeServiceTable;
use crate::{ArrowClientEventListener, ConnectionState};

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

/// Helper function.
fn connection_state_to_c_int(state: ConnectionState) -> c_int {
    match state {
        ConnectionState::Disconnected => 0,
        ConnectionState::Connected => 1,
        ConnectionState::Unauthorized => 2,
    }
}

/// Type alias.
type ConnectionStateCallback = unsafe extern "C" fn(opaque: *mut c_void, state: c_int);

/// Helper struct.
struct ConnectionStateListener {
    callback: ConnectionStateCallback,
    opaque: *mut c_void,
}

impl ConnectionStateListener {
    /// Create a new connection state listener.
    fn new(opaque: *mut c_void, callback: ConnectionStateCallback) -> Self {
        Self { opaque, callback }
    }
}

impl ArrowClientEventListener for ConnectionStateListener {
    fn connection_state_changed(&mut self, state: ConnectionState) {
        unsafe { (self.callback)(self.opaque, connection_state_to_c_int(state)) }
    }
}

unsafe impl Send for ConnectionStateListener {}

/// Type alias.
type NetworkScannerStateCallback = unsafe extern "C" fn(opaque: *mut c_void, scanning: c_int);

/// Helper struct.
struct NetworkScannerStateListener {
    callback: NetworkScannerStateCallback,
    opaque: *mut c_void,
}

impl NetworkScannerStateListener {
    /// Create a new network scanner state listener.
    fn new(opaque: *mut c_void, callback: NetworkScannerStateCallback) -> Self {
        Self { opaque, callback }
    }
}

impl ArrowClientEventListener for NetworkScannerStateListener {
    fn network_scanner_state_changed(&mut self, scanning: bool) {
        unsafe { (self.callback)(self.opaque, c_int::from(scanning)) }
    }
}

unsafe impl Send for NetworkScannerStateListener {}

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

    if let Ok(config) = builder.build(*storage, arrow_service_address) {
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
    (*client).client.close();
}

/// Add a given connection state callback.
#[no_mangle]
pub unsafe extern "C" fn ac__arrow_client__add_connection_state_callback(
    client: *mut NativeArrowClient,
    callback: ConnectionStateCallback,
    opaque: *mut c_void,
) {
    (*client)
        .client
        .add_event_listener(ConnectionStateListener::new(opaque, callback))
}

/// Add a given network scanner state callback.
#[no_mangle]
pub unsafe extern "C" fn ac__arrow_client__add_network_scanner_state_callback(
    client: *mut NativeArrowClient,
    callback: NetworkScannerStateCallback,
    opaque: *mut c_void,
) {
    (*client)
        .client
        .add_event_listener(NetworkScannerStateListener::new(opaque, callback))
}

/// Get Arrow client UUID. The given buffer must have enough space to store at least 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn ac__arrow_client__get_uuid(
    client: *const NativeArrowClient,
    buffer: *mut u8,
) {
    let uuid = (*client).client.get_arrow_uuid();
    let uuid = uuid.as_bytes().as_ref();
    let buffer = slice::from_raw_parts_mut(buffer, uuid.len());

    buffer.copy_from_slice(uuid);
}

/// Get MAC address used for Arrow client identification. The given buffer must have enough space
/// to store at least 6 bytes.
#[no_mangle]
pub unsafe extern "C" fn ac__arrow_client__get_mac_address(
    client: *const NativeArrowClient,
    buffer: *mut u8,
) {
    let mac = (*client).client.get_mac_address().octets();
    let buffer = slice::from_raw_parts_mut(buffer, mac.len());

    buffer.copy_from_slice(&mac);
}

/// Get client service table.
#[no_mangle]
pub unsafe extern "C" fn ac__arrow_client__get_service_table(
    client: *const NativeArrowClient,
) -> *mut NativeServiceTable {
    let table = (*client).client.get_service_table();

    Box::into_raw(Box::new(NativeServiceTable::from(table)))
}

/// Scan the local network.
#[no_mangle]
pub unsafe extern "C" fn ac__arrow_client__scan_network(client: *mut NativeArrowClient) {
    (*client).client.scan_network();
}

/// Clear the service table and scan the local network again.
#[no_mangle]
pub unsafe extern "C" fn ac__arrow_client__rescan_network(client: *mut NativeArrowClient) {
    (*client).client.rescan_network();
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
