// Copyright 2015 click2stream, Inc.
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

//! PCAP network scanner definitions.

use std::fmt;
use std::ptr;
use std::slice;
use std::sync::mpsc;
use std::thread;

use std::error::Error;
use std::ffi::{CStr, CString};
use std::fmt::{Display, Formatter};
use std::os::raw::{c_char, c_int, c_void};
use std::sync::mpsc::Sender;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};

use crate::net::raw::ether::packet::EtherPacket;

type PacketCallback = unsafe extern "C" fn(
    opaque: *mut c_void,
    data: *const u8,
    data_length: usize,
    packet_length: usize,
);

extern "C" {
    fn pcap_wrapper__new(device: *const c_char) -> *mut c_void;
    fn pcap_wrapper__free(wrapper: *mut c_void);

    fn pcap_wrapper__get_last_error(wrapper: *const c_void) -> *const c_char;

    fn pcap_wrapper__set_filter(wrapper: *mut c_void, filter: *const c_char) -> c_int;
    fn pcap_wrapper__set_max_packet_length(wrapper: *mut c_void, max_packet_length: usize);
    fn pcap_wrapper__set_read_timeout(wrapper: *mut c_void, read_timeout: u64);

    fn pcap_wrapper__open(wrapper: *mut c_void) -> c_int;

    fn pcap_wrapper__read_packet(
        wrapper: *mut c_void,
        callback: PacketCallback,
        opaque: *mut c_void,
    ) -> c_int;
    fn pcap_wrapper__write_packet(wrapper: *mut c_void, data: *const u8, size: usize) -> c_int;
}

lazy_static! {
    /// PCAP context for synchronizing thread unsafe calls.
    static ref TC: Mutex<()> = Mutex::new(());
}

/// PCAP error.
#[derive(Debug, Clone)]
pub struct PcapError {
    msg: String,
}

impl PcapError {
    /// Create a new error with a given error message.
    pub fn new<T>(msg: T) -> Self
    where
        T: ToString,
    {
        Self {
            msg: msg.to_string(),
        }
    }
}

impl Display for PcapError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str(&self.msg)
    }
}

impl Error for PcapError {}

/// Common result type for this module.
pub type Result<T> = std::result::Result<T, PcapError>;

/// Capture builder.
struct CaptureBuilder {
    inner: Capture,
}

impl CaptureBuilder {
    /// Create a new capture builder for a given device.
    fn new(device: &str) -> Self {
        let device = CString::new(device).unwrap();

        let ptr = unsafe { pcap_wrapper__new(device.as_ptr()) };

        if ptr.is_null() {
            panic!("Unable to allocate PCAP capture device");
        }

        let capture = Capture { ptr };

        Self { inner: capture }
    }

    /// Set maximum packet length (longer packets will be truncated).
    pub fn max_packet_length(self, max_packet_length: usize) -> Self {
        unsafe {
            pcap_wrapper__set_max_packet_length(self.inner.ptr, max_packet_length as _);
        }

        self
    }

    /// Set read timeout in milliseconds (i.e. the amount of time that the `read_packet()` method
    /// can block).
    pub fn read_timeout(self, read_timeout: u64) -> Self {
        unsafe {
            pcap_wrapper__set_read_timeout(self.inner.ptr, read_timeout);
        }

        self
    }

    /// Set packet filter.
    pub fn filter(self, filter: Option<&str>) -> Self {
        let filter = filter.map(|s| CString::new(s).unwrap());

        let filter_ptr = filter.as_ref().map(|f| f.as_ptr()).unwrap_or(ptr::null());

        let ret = unsafe { pcap_wrapper__set_filter(self.inner.ptr, filter_ptr) };

        if ret != 0 {
            panic!("Unable to allocate a packet filter");
        }

        self
    }

    /// Activate the capture.
    pub fn activate(self) -> Result<Capture> {
        let _tc = TC.lock().unwrap();

        let ret = unsafe { pcap_wrapper__open(self.inner.ptr) };

        if ret == 0 {
            Ok(self.inner)
        } else {
            Err(self.inner.get_last_error())
        }
    }
}

/// Capture handle that can be used for reading and writing raw packets.
struct Capture {
    ptr: *mut c_void,
}

impl Capture {
    /// Get a builder.
    pub fn builder(device: &str) -> CaptureBuilder {
        CaptureBuilder::new(device)
    }

    /// Read one packet. The packet will be appended to a given buffer. True will be returned if a
    /// packet was read, false will be returned in case of timeout.
    pub fn read_packet(&mut self, buffer: &mut BytesMut) -> Result<bool> {
        let buffer_ptr: *mut BytesMut = buffer;

        let ret =
            unsafe { pcap_wrapper__read_packet(self.ptr, read_packet_callback, buffer_ptr as _) };

        if ret >= 0 {
            Ok(ret > 0)
        } else {
            Err(self.get_last_error())
        }
    }

    /// Write a given packet to the underlying network device.
    pub fn write_packet(&mut self, packet: &[u8]) -> Result<()> {
        let data = packet.as_ptr();
        let size = packet.len();

        let ret = unsafe { pcap_wrapper__write_packet(self.ptr, data, size as _) };

        if ret == 0 {
            Ok(())
        } else {
            Err(self.get_last_error())
        }
    }

    /// Get last error.
    fn get_last_error(&self) -> PcapError {
        unsafe {
            let ptr = pcap_wrapper__get_last_error(self.ptr);
            let msg = CStr::from_ptr(ptr);

            PcapError::new(msg.to_string_lossy())
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        unsafe { pcap_wrapper__free(self.ptr) }
    }
}

/// Helper callback for getting packet data.
unsafe extern "C" fn read_packet_callback(
    opaque: *mut c_void,
    data: *const u8,
    data_length: usize,
    _: usize,
) {
    let buffer_ptr = opaque as *mut BytesMut;

    let data = slice::from_raw_parts(data, data_length as _);

    (*buffer_ptr).extend_from_slice(data);
}

/// PCAP packet scanner (implementation of a send-receive service).
pub struct Scanner {
    device: String,
}

impl Scanner {
    /// Create a new PCAP scanner for a given device.
    pub fn new(device: &str) -> Self {
        Self {
            device: device.to_string(),
        }
    }

    /// Send all packets from a given iterator and receive all packets
    /// according to a given filter.
    pub fn sr<F>(
        &mut self,
        filter: &str,
        packet_generator: F,
        read_timeout: Duration,
        stop_after: Option<Duration>,
    ) -> Result<Vec<EtherPacket>>
    where
        F: FnMut() -> Option<Bytes>,
    {
        let device = self.device.clone();
        let filter = filter.to_string();

        // NOTE: we need to synchronize the sender and the receiver parts to avoid sending out
        // packets before the receiver is initialized (otherwise we could miss some response
        // packets)
        let (tx, rx) = mpsc::channel();

        let t = thread::spawn(move || {
            packet_listener(&device, &filter, read_timeout, stop_after, Some(tx))
        });

        rx.recv().unwrap_or_default();

        send_packets(&self.device, packet_generator)?;

        t.join().unwrap()
    }
}

/// Listen for incoming packets matching a given filter until no packets are read for a given
/// soft timeout or until a given hard timeout expires.
///
/// # Arguments
/// * `device` - device name
/// * `filter` - packet filter expression
/// * `packet_timeout` - a soft timeout that will stop the listener if no packet is received for
///   given duration
/// * `total_timeout` - a hard timeout that will stop the listener when it expires
/// * `init_event_tx` - an optional sender that will be used to notify another thread that the
///   listener has been initialized and is receiving packets
fn packet_listener(
    device: &str,
    filter: &str,
    packet_timeout: Duration,
    total_timeout: Option<Duration>,
    init_event_tx: Option<Sender<()>>,
) -> Result<Vec<EtherPacket>> {
    let mut cap = Capture::builder(device)
        .max_packet_length(65_536)
        .read_timeout(100)
        .filter(Some(filter))
        .activate()?;

    if let Some(tx) = init_event_tx {
        tx.send(()).unwrap_or_default();
    }

    let start_time = Instant::now();

    let mut last_packet_time = Instant::now();
    let mut buffer = BytesMut::new();
    let mut res = Vec::new();

    loop {
        if cap.read_packet(&mut buffer)? {
            last_packet_time = Instant::now();

            if let Ok(packet) = EtherPacket::parse(buffer.as_ref()) {
                res.push(packet);
            }

            buffer.clear();
        }

        if let Some(timeout) = total_timeout {
            if start_time.elapsed() > timeout {
                break;
            }
        }

        if last_packet_time.elapsed() > packet_timeout {
            break;
        }
    }

    Ok(res)
}

/// Send all packets using a given network device.
fn send_packets<F>(device: &str, mut packet_generator: F) -> Result<()>
where
    F: FnMut() -> Option<Bytes>,
{
    let mut cap = Capture::builder(device).activate()?;

    while let Some(pkt) = packet_generator() {
        cap.write_packet(pkt.as_ref())?;
    }

    Ok(())
}
