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
use std::collections::HashSet;
use std::collections::HashMap;
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
use net::raw::icmp::scanner::IcmpScanner;
use net::raw::tcp::scanner::{TcpPortScanner, PortCollection};
use net::rtsp::sdp::{SessionDescription, MediaType, RTPMap, FromAttribute};

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

/// RTSP port candidates.
static RTSP_PORT_CANDIDATES: &'static [u16] = &[
      554,    88,    81,   555,  7447, 
     8554,  7070, 10554,    80
];

/// Find all RTSP streams in all local networks.
pub fn find_rtsp_streams() -> Result<Vec<Service>> {
    let tc      = pcap::new_threading_context();
    let devices = EthernetDevice::list();
    
    let port_candidates = PortCollection::new()
        .add_all(RTSP_PORT_CANDIDATES);
    
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
    
    // note: we permit only one RTSP service per host (some stupid RTSP servers 
    // are accessible from more than one port and they tend to crash when they 
    // are accessed from the "incorrect" one)
    let rtsp_services   = try!(find_rtsp_services(&services));
    let port_priorities = get_port_priorities(RTSP_PORT_CANDIDATES);
    let rtsp_services   = filter_duplicit_services(
        &rtsp_services,
        &port_priorities);
    
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
            Ok(svc) => res.push(try!(svc))
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

/// Check if a given session description contains at least one H.264 or 
/// a general MPEG4 video stream.
fn is_supported_service(sdp: &[u8]) -> bool {
    if let Ok(sdp) = SessionDescription::parse(sdp) {
        let mut vcodecs   = HashSet::new();
        let video_streams = sdp.media_descriptions.into_iter()
            .filter(|md| md.media_type == MediaType::Video);
        
        for md in video_streams {
            for attr in md.attributes {
                if let Ok(rtpmap) = RTPMap::parse(&attr) {
                    vcodecs.insert(rtpmap.encoding.to_uppercase());
                }
            }
        }
        
        vcodecs.contains("H264") ||
            vcodecs.contains("H264-RCDO") ||
            vcodecs.contains("H264-SVC") ||
            vcodecs.contains("MP4V-ES") ||
            vcodecs.contains("MPEG4-GENERIC")
    } else {
        false
    }
}

/// RTSP DESCRIBE status.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum DescribeStatus {
    Ok,
    Locked,
    Unsupported,
    NotFound,
    Error
}

/// Get describe status code for a given RTSP service and path.
fn get_describe_status(addr: SocketAddr, path: &str) -> Result<DescribeStatus> {
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
            Ok(DescribeStatus::NotFound)
        } else {
            match header.code {
                404 => Ok(DescribeStatus::NotFound),
                401 => Ok(DescribeStatus::Locked),
                200 if is_supported_service(&response.body) => 
                    Ok(DescribeStatus::Ok),
                200 => Ok(DescribeStatus::Unsupported),
                _   => Ok(DescribeStatus::Error)
            }
        }
    } else {
        Ok(DescribeStatus::Error)
    }
}

/// Find open ports on all available hosts within a given network and port 
/// range.
fn find_services(
    pc: pcap::ThreadingContext,
    device: &EthernetDevice,
    ports: &PortCollection) -> Result<Vec<Socket>> {
    let mut hosts  = HashSet::new();
    let arp_hosts  = try!(Ipv4ArpScanner::scan_device(pc.clone(), device));
    let icmp_hosts = try!(IcmpScanner::scan_device(pc.clone(), device));
    
    hosts.extend(arp_hosts);
    hosts.extend(icmp_hosts);
    
    let res = try!(find_open_ports(pc, device, 
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
    paths: &[String]) -> Result<Service> {
    let mut service = Service::UnknownRTSP(mac, addr);
    
    for path in paths {
        let status = try!(get_describe_status(addr, path));
        if status == DescribeStatus::Ok {
            service = Service::RTSP(mac, addr, path.to_string());
        } else if status == DescribeStatus::Unsupported {
            service = Service::UnsupportedRTSP(mac, addr, path.to_string());
        } else if status == DescribeStatus::Locked {
            service = Service::LockedRTSP(mac, addr);
        }
        
        match status {
            DescribeStatus::Ok     => break,
            DescribeStatus::Locked => break,
            _ => ()
        }
    }
    
    Ok(service)
}

/// Assuming the given list of ports is sorted according to port priority 
/// (from highest to lowest), get a map of port -> port_priority pairs.
fn get_port_priorities(ports: &[u16]) -> HashMap<u16, usize> {
    let mut res = HashMap::new();
    let len = ports.len();
    for i in 0..len {
        res.insert(ports[i], len - i);
    }
    
    res
}

/// Filter out duplicit services from a given list using given priorities.
fn filter_duplicit_services(
    services: &[Socket], 
    port_priorities: &HashMap<u16, usize>) -> Vec<Socket> {
    let mut svc_map = HashMap::new();
    
    for &(ref mac, ref saddr) in services {
        let mac  = *mac;
        let ip   = *saddr.ip();
        let port = saddr.port();
        
        if svc_map.contains_key(&ip) {
            let old_port = svc_map.get(&ip)
                .map(|&(_, _, ref port)| *port)
                .unwrap_or(0);
            let old_priority = port_priorities.get(&old_port)
                .map(|priority| *priority)
                .unwrap_or(0);
            let new_priority = port_priorities.get(&port)
                .map(|priority| *priority)
                .unwrap_or(0);
            if new_priority > old_priority {
                svc_map.insert(ip, (mac, ip, port));
            }
        } else {
            svc_map.insert(ip, (mac, ip, port));
        }
    }
    
    svc_map.into_iter()
        .map(|(_, (mac, ip, port))| (mac, SocketAddrV4::new(ip, port)))
        .collect::<_>()
}

#[cfg(test)]
#[test]
/// Test the service priority filtering function.
fn test_service_filtering() {
    let ports = [554, 80];
    let mac   = MacAddr::new(0, 0, 0, 0, 0, 0);
    let ip    = Ipv4Addr::new(0, 0, 0, 0);
    
    let mut services = Vec::new();
    
    services.push((mac, SocketAddrV4::new(ip, 80)));
    services.push((mac, SocketAddrV4::new(ip, 554)));
    
    let port_priorities = get_port_priorities(&ports);
    let services = filter_duplicit_services(&services, &port_priorities);
    
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].1.port(), 554);
}
