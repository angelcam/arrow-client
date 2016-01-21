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

///! Network scanner for RTSP streams.

use std::io;
use std::fmt;
use std::thread;
use std::result;

use std::fs::File;
use std::sync::Arc;
use std::error::Error;
use std::io::{BufReader, BufRead};
use std::fmt::{Display, Formatter};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use net::rtsp;
use net::raw::pcap;

use net::rtsp::Client as RtspClient;
use net::raw::devices::EthernetDevice;
use net::raw::ether::MacAddr;
use net::arrow::protocol::Service;
use net::raw::arp::scanner::Ipv4ArpScanner;
use net::raw::tcp::scanner::{TcpPortScanner, PortCollection};

static RTSP_PATH_FILE: &'static str = "/etc/arrow/rtsp-paths";

/// Discovery error.
#[derive(Debug, Clone)]
pub struct DiscoveryError {
    msg: String,
}

impl Error for DiscoveryError {
    fn description(&self) -> &str {
        &self.msg
    }
}

impl Display for DiscoveryError {
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        f.write_str(&self.msg)
    }
}

impl From<String> for DiscoveryError {
    fn from(msg: String) -> DiscoveryError {
        DiscoveryError { msg: msg }
    }
}

impl<'a> From<&'a str> for DiscoveryError {
    fn from(msg: &'a str) -> DiscoveryError {
        DiscoveryError { msg: msg.to_string() }
    }
}

impl From<rtsp::RtspError> for DiscoveryError {
    fn from(err: rtsp::RtspError) -> DiscoveryError {
        DiscoveryError::from(format!("RTSP client error: {}", 
            err.description()))
    }
}

impl From<pcap::PcapError> for DiscoveryError {
    fn from(err: pcap::PcapError) -> DiscoveryError {
        DiscoveryError::from(format!("pcap error: {}", err.description()))
    }
}

impl From<io::Error> for DiscoveryError {
    fn from(err: io::Error) -> DiscoveryError {
        DiscoveryError::from(format!("IO error: {}", err.description()))
    }
}

/// Discovery result type alias.
pub type Result<T> = result::Result<T, DiscoveryError>;

/// Discovery host type alias.
type Host = (MacAddr, Ipv4Addr);
/// Discovery service type alias.
type Socket = (MacAddr, SocketAddrV4);

/// Find all RTSP streams in all local networks.
pub fn find_rtsp_streams() -> Result<Vec<Service>> {
    let tc      = pcap::new_threading_context();
    let devices = EthernetDevice::list();
    
    let port_candidates = PortCollection::new()
        .add_all(&[554, 88, 81, 555, 7447, 8554, 7070, 10554, 80]);
    
    let mut threads = Vec::new();
    
    for dev in devices {
        let pc     = port_candidates.clone();
        let tc     = tc.clone();
        let handle = thread::spawn(move || {
            find_services(tc, &dev, &pc)
        });
        
        threads.push(handle);
    }
    
    let mut services = Vec::new();
    
    for handle in threads {
        match handle.join() {
            Err(_)  => return Err(DiscoveryError::from("port scanner thread panicked")),
            Ok(res) => services.extend(try!(res))
        }
    }
    
    let rtsp_services = try!(find_rtsp_services(&services));
    
    let mut threads = Vec::new();
    let paths       = Arc::new(try!(load_rtsp_paths(RTSP_PATH_FILE)));
    
    for (mac, addr) in rtsp_services {
        let addr   = SocketAddr::V4(addr);
        let paths  = paths.clone();
        let handle = thread::spawn(move || {
            find_rtsp_paths(mac, addr, &paths)
        });
        threads.push(handle);
    }
    
    let mut res = Vec::new();
    
    for handle in threads {
        match handle.join() {
            Err(_) => return Err(DiscoveryError::from(
                "path testing thread panicked")),
            Ok(svc) => res.extend(try!(svc))
        }
    }
    
    Ok(res)
}

/// Load all known RTSP path variants from a given file.
fn load_rtsp_paths(file: &str) -> Result<Vec<String>> {
    let file      = try!(File::open(file));
    let breader   = BufReader::new(file);
    let mut paths = Vec::new();
    
    for line in breader.lines() {
        let path = try!(line);
        if !path.starts_with('#') {
            paths.push(path);
        }
    }
    
    Ok(paths)
}

/// Check if a given service is an RTSP service.
fn is_rtsp_service(addr: SocketAddr) -> Result<bool> {
    let mut client = try!(RtspClient::new(addr));
    client.set_timeout(Some(1000));
    Ok(client.options().is_ok())
}

/// Get describe status code for a given RTSP service and path.
fn get_describe_status(addr: SocketAddr, path: &str) -> Result<Option<i32>> {
    let mut client = try!(RtspClient::new(addr));
    client.set_timeout(Some(1000));
    if let Ok(response) = client.describe(path) {
        let header = response.header;
        let hipcam = match header.get_str("Server") {
            Some("HiIpcam/V100R003 VodServer/1.0.0") => true,
            Some("Hipcam RealServer/V1.0")           => true,
            _ => false
        };
        
        if hipcam && path != "/11" && path != "/12" {
            Ok(None)
        } else {
            Ok(Some(header.code))
        }
    } else {
        Ok(None)
    }
}

/// Find open ports on all available hosts within a given network and port 
/// range.
fn find_services(
    pc: pcap::ThreadingContext,
    device: &EthernetDevice,
    ports: &PortCollection) -> Result<Vec<Socket>> {
    let hosts = try!(Ipv4ArpScanner::scan_device(pc.clone(), device));
    let res   = try!(find_open_ports(pc, device, 
        hosts.into_iter(), ports));
    
    Ok(res)
}

/// Check if any of given TCP ports is open on on any host from a given set.
fn find_open_ports<HI: Iterator<Item=Host>>(
    pc: pcap::ThreadingContext,
    device: &EthernetDevice,
    hosts: HI, 
    ports: &PortCollection) -> Result<Vec<Socket>> {
    let res = try!(TcpPortScanner::scan_ipv4_hosts(pc, device, hosts, ports))
        .into_iter()
        .map(|(mac, ip, p)| (mac, SocketAddrV4::new(ip, p)))
        .collect::<Vec<_>>();
    
    Ok(res)
}

/// Find all RTSP services among a given set of sockets.
fn find_rtsp_services(sockets: &[Socket]) -> Result<Vec<Socket>> {
    let mut threads = Vec::new();
    let mut res     = Vec::new();
    
    for &(mac, addr) in sockets {
        let handle = thread::spawn(move || {
            (mac, addr, is_rtsp_service(SocketAddr::V4(addr)))
        });
        threads.push(handle);
    }
    
    for handle in threads {
        match handle.join() {
            Err(_) => return Err(DiscoveryError::from("RTSP service testing thread panicked")),
            Ok((mac, addr, rtsp)) => {
                if try!(rtsp) {
                    res.push((mac, addr))
                }
            }
        }
    }
    
    Ok(res)
}

/// Find all available RTSP paths for a given RTSP service.
fn find_rtsp_paths(
    mac: MacAddr, 
    addr: SocketAddr, 
    paths: &[String]) -> Result<Vec<Service>> {
    let mut res    = Vec::new();
    let mut locked = false;
    for path in paths {
        match try!(get_describe_status(addr, path)) {
            Some(200) => res.push(path.to_string()),
            Some(401) => locked = true,
            _ => ()
        }
    }
    
    let res = if locked {
        vec![Service::LockedRTSP(mac, addr)]
    } else if res.is_empty() {
        vec![Service::UnknownRTSP(mac, addr)]
    } else {
        res.into_iter()
            .map(|path| Service::RTSP(mac, addr, path))
            .collect::<Vec<_>>()
    };
    
    Ok(res)
}
