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

use std::ptr;
use std::fmt;
use std::thread;
use std::result;
use std::slice;

use std::error::Error;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::ffi::CString;
use std::fmt::{Display, Formatter};
use std::time::Duration;

use net::raw::ether::packet::EtherPacket;

use utils;

use bytes::Bytes;

use libc;

use libc::pollfd;
use libc::POLLIN;
use libc::{c_int, c_uint, c_long, c_char, c_uchar, c_void, size_t};

/// PCAP module error.
#[derive(Debug)]
pub struct PcapError {
    msg: String,
}

impl PcapError {
    unsafe fn from_cstr(msg: *const c_char) -> PcapError {
        PcapError { msg: utils::cstr_to_string(msg as *const _) }
    }

    fn from_pcap(p: pcap_t) -> PcapError {
        unsafe {
            let cstr = pcap_geterr(p);
            Self::from_cstr(cstr)
        }
    }
}

impl Error for PcapError {
    fn description(&self) -> &str {
        &self.msg
    }
}

impl Display for PcapError {
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        f.write_str(&self.msg)
    }
}

impl<'a> From<&'a str> for PcapError {
    fn from(msg: &'a str) -> PcapError {
        PcapError { msg: msg.to_string() }
    }
}

pub type Result<T> = result::Result<T, PcapError>;

#[allow(non_camel_case_types)]
type pcap_t      = *mut c_void;
#[allow(non_camel_case_types)]
type bpf_u_int32 = c_uint;
#[allow(non_camel_case_types)]
type time_t      = c_long;
#[allow(non_camel_case_types)]
type suseconds_t = c_long;

#[allow(non_camel_case_types)]
type pcap_handler = unsafe extern "C" fn(*mut c_uchar, *const pcap_pkthdr, *const c_uchar);

#[repr(C)]
#[allow(non_camel_case_types)]
struct timeval {
    tv_sec:  time_t,
    tv_usec: suseconds_t,
}

#[repr(C)]
#[allow(non_camel_case_types)]
struct pcap_pkthdr {
    ts:     timeval,
    caplen: bpf_u_int32,
    len:    bpf_u_int32,
}

#[repr(C)]
#[allow(non_camel_case_types)]
struct bpf_program {
    bf_len:   c_uint,
    bf_insns: *mut c_void,
}

impl bpf_program {
    fn new() -> bpf_program {
        bpf_program {
            bf_len:   0,
            bf_insns: ptr::null_mut()
        }
    }
}

extern "C" {
    fn pcap_create(source: *const c_char, errbuf: *mut c_char) -> pcap_t;
    fn pcap_activate(p: pcap_t) -> c_int;
    fn pcap_close(p: pcap_t) -> c_void;
    fn pcap_geterr(p: pcap_t) -> *const c_char;
    fn pcap_set_promisc(p: pcap_t, promisc: c_int) -> c_int;
    fn pcap_set_timeout(p: pcap_t, ms: c_int) -> c_int;
    fn pcap_setnonblock(p: pcap_t, nonblock: c_int, errbuf: *mut c_char) -> c_int;
    fn pcap_dispatch(
        p: pcap_t,
        cnt: c_int,
        callback: pcap_handler,
        misc: *mut c_uchar) -> c_int;
    fn pcap_compile(
        p: pcap_t,
        prog: *mut bpf_program,
        pstr: *const c_char,
        optimize: c_int,
        netmask: bpf_u_int32) -> c_int;
    fn pcap_freecode(prog: *mut bpf_program) -> c_void;
    fn pcap_setfilter(p: pcap_t, prog: *mut bpf_program) -> c_int;
    fn pcap_inject(p: pcap_t, buf: *const c_void, size: size_t) -> c_int;
    fn pcap_get_selectable_fd(p: pcap_t) -> c_int;
}

/// PCAP context for synchronizing thread unsafe calls.
struct Context;

lazy_static!{
    /// PCAP context for synchronizing thread unsafe calls.
    static ref TC: Arc<Mutex<Context>> = {
        Arc::new(Mutex::new(Context))
    };
}

/// PCAP Capture builder.
struct CaptureBuilder {
    capture: Capture,
}

impl CaptureBuilder {
    /// Create a new CaptureBuilder for a given device.
    fn new(dname: &str) -> Result<CaptureBuilder> {
        let mut result = CaptureBuilder {
            capture: Capture {
                errbuf: Box::new([0; 4096]),
                h:      ptr::null_mut()
            }
        };

        let dname_cstr = CString::new(dname).unwrap();
        let dname_ptr = dname_cstr.as_ptr() as *const c_char;
        let errbuf_ptr = result.capture.errbuf.as_mut_ptr();
        result.capture.h = unsafe {
            pcap_create(dname_ptr, errbuf_ptr as *mut c_char)
        };

        if result.capture.h.is_null() {
            Err(unsafe { PcapError::from_cstr(errbuf_ptr as *const c_char) })
        } else {
            Ok(result)
        }
    }

    /// Set promiscuous mode.
    fn promisc(self, p: bool) -> CaptureBuilder {
        unsafe { pcap_set_promisc(self.capture.h, p as c_int); }
        self
    }

    /// Set packet buffer timeout.
    fn timeout(self, ms: i32) -> CaptureBuilder {
        unsafe { pcap_set_timeout(self.capture.h, ms as c_int); }
        self
    }

    /// Activate.
    fn activate(self) -> Result<Capture> {
        let ret = unsafe { pcap_activate(self.capture.h) };
        match ret {
            0 => Ok(self.capture),
            _ => Err(PcapError::from_pcap(self.capture.h))
        }
    }
}

/// PCAP capture.
struct Capture {
    errbuf: Box<[c_char; 4096]>,
    h:      pcap_t,
}

impl Capture {
    /// Start capturing packets (at most count) and pass them to a given callback.
    fn dispatch<F>(&mut self, count: usize, callback: F) -> Result<usize>
        where F: FnMut(&[u8]) {
        let mut callback: Box<FnMut(&[u8])> = Box::new(callback);

        let misc = &mut callback as *mut Box<FnMut(&[u8])>;

        let res = unsafe {
            pcap_dispatch(
                self.h,
                count as c_int,
                capture_packet_callback,
                misc as *mut c_uchar)
        };

        if res < 0 {
            Err(PcapError::from_pcap(self.h))
        } else {
            Ok(res as usize)
        }
    }

    /// Poll the internal file descriptor.
    fn poll(&mut self, timeout: u64) {
        unsafe {
            let fd = pcap_get_selectable_fd(self.h);

            // on some systems, there is no selectable file descriptor
            if fd < 0 {
                thread::sleep(Duration::from_millis(timeout))
            } else {
                // input/output for the poll function
                let mut fds = pollfd {
                    fd: fd,
                    events: POLLIN,
                    revents: 0,
                };

                libc::poll(&mut fds, 1, timeout as _);
            }
        }
    }

    /// Set the underlaying file descriptor into non-blocking mode.
    fn set_non_blocking(&mut self, non_blocking: bool) -> Result<()> {
        let mut errbuf = [0; 4096];

        unsafe {
            let eb = errbuf.as_mut_ptr();
            let nb = match non_blocking {
                true  => 1,
                false => 0,
            };

            if pcap_setnonblock(self.h, nb, eb) < 0 {
                Err(PcapError::from_cstr(eb))
            } else {
                Ok(())
            }
        }
    }

    /// Set packet filter.
    fn filter(&mut self, f: &str) -> Result<()> {
        unsafe {
            let mut prog = self.compile_filter(f)?;

            let ret = pcap_setfilter(self.h, &mut prog);

            pcap_freecode(&mut prog);

            match ret {
                0 => Ok(()),
                _ => Err(PcapError::from_pcap(self.h))
            }
        }
    }

    /// Inject a given raw packet.
    fn inject(&mut self, data: &[u8]) -> Result<usize> {
        let ptr = data.as_ptr() as *const c_void;
        let ret = unsafe {
            pcap_inject(self.h, ptr, data.len() as size_t)
        };

        if ret < 0 {
            Err(PcapError::from_pcap(self.h))
        } else {
            Ok(ret as usize)
        }
    }

    /// Compile a given filter string.
    unsafe fn compile_filter(&mut self, f: &str) -> Result<bpf_program> {
        let _lock = TC.lock()
            .unwrap();

        let f_cstr = CString::new(f).unwrap();
        let f_ptr = f_cstr.as_ptr() as *const c_char;

        let mut prog = bpf_program::new();

        match pcap_compile(self.h, &mut prog, f_ptr, 0, 0) {
            0 => Ok(prog),
            _ => Err(PcapError::from_pcap(self.h))
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        if !self.h.is_null() {
            unsafe { pcap_close(self.h); }
        }
    }
}

unsafe impl Send for Capture {
}

unsafe extern "C" fn capture_packet_callback(
    misc: *mut c_uchar,
    header: *const pcap_pkthdr,
    data: *const c_uchar) {
    let callback = misc as *mut Box<FnMut(&[u8])>;
    let header   = &*header;

    let data = slice::from_raw_parts(
        data as *const u8,
        header.caplen as usize);

    (*callback)(data);
}

/// PCAP packet scanner (implementation of a send-receive service).
pub struct Scanner {
    device: String,
}

impl Scanner {
    /// Create a new PCAP scanner for a given device.
    pub fn new(device: &str) -> Scanner {
        Scanner {
            device: device.to_string(),
        }
    }

    /// Send all packets from a given iterator and receive all packets
    /// according to a given filter.
    pub fn sr<F>(
        &mut self,
        filter: &str,
        packet_generator: F,
        timeout: u64) -> Result<Vec<EtherPacket>>
    where
        F: FnMut() -> Option<Bytes>,
    {
        let end_indicator = Arc::new(AtomicBool::new(false));

        let device = self.device.clone();
        let filter = filter.to_string();
        let ei_handle = end_indicator.clone();

        let t = thread::spawn(move || {
            packet_listener(&device, &filter, ei_handle)
        });

        send_packets(&self.device, packet_generator)?;

        // give the packet listener some time to collect incoming packets
        thread::sleep(Duration::from_millis(timeout));

        end_indicator.store(true, Ordering::SeqCst);

        t.join().map_err(|_| PcapError::from("listener thread panicked"))?
    }
}

/// Listen for incoming packets matching a given filter until a given end
/// indicator is set.
fn packet_listener(
    device: &str,
    filter: &str,
    end_indicator: Arc<AtomicBool>) -> Result<Vec<EtherPacket>> {
    let mut cap = CaptureBuilder::new(device)?
        .timeout(100)
        .promisc(true)
        .activate()?;

    cap.filter(filter)?;
    cap.set_non_blocking(true)?;

    let mut res = Vec::new();

    {
        let mut callback = |data: &[u8]| {
            if let Ok(packet) = EtherPacket::parse(data) {
                res.push(packet);
            }
        };

        while !end_indicator.load(Ordering::SeqCst) {
            let count = cap.dispatch(1, &mut callback)?;

            if count == 0 {
                cap.poll(100);
            }
        }
    }

    Ok(res)
}

/// Send all packets using a given network device. This call is blocking.
fn send_packets<F>(device: &str, mut packet_generator: F) -> Result<()>
where
    F: FnMut() -> Option<Bytes>,
{
    let mut cap = CaptureBuilder::new(device)?
        .activate()?;

    while let Some(pkt) = packet_generator() {
        cap.inject(pkt.as_ref())?;
    }

    Ok(())
}
