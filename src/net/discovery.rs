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
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};

use net::http;
use net::rtsp;
use net::raw::pcap;

use net::http::Client as HttpClient;
use net::rtsp::Client as RtspClient;
use net::raw::devices::EthernetDevice;
use net::raw::ether::MacAddr;
use net::raw::arp::scanner::Ipv4ArpScanner;
use net::raw::icmp::scanner::IcmpScanner;
use net::arrow::protocol::{Service, ScanReport};
use net::arrow::protocol::{HINFO_FLAG_ARP, HINFO_FLAG_ICMP};
use net::raw::tcp::scanner::{TcpPortScanner, PortCollection};
use net::rtsp::sdp::{SessionDescription, MediaType, RTPMap, FromAttribute};

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
        DiscoveryError::from(msg.to_string())
    }
}

impl From<http::HttpError> for DiscoveryError {
    fn from(err: http::HttpError) -> DiscoveryError {
        DiscoveryError::from(format!("HTTP client error: {}", err))
    }
}

impl From<rtsp::RtspError> for DiscoveryError {
    fn from(err: rtsp::RtspError) -> DiscoveryError {
        DiscoveryError::from(format!("RTSP client error: {}", err))
    }
}

impl From<pcap::PcapError> for DiscoveryError {
    fn from(err: pcap::PcapError) -> DiscoveryError {
        DiscoveryError::from(format!("pcap error: {}", err.description()))
    }
}

impl From<io::Error> for DiscoveryError {
    fn from(err: io::Error) -> DiscoveryError {
        DiscoveryError::from(format!("IO error: {}", err))
    }
}

/// Discovery result type alias.
pub type Result<T> = result::Result<T, DiscoveryError>;

/// RTSP port candidates.
static RTSP_PORT_CANDIDATES: &'static [u16] = &[
      554,    88,    81,   555,  7447, 
     8554,  7070, 10554,    80
];

/// Find all RTSP streams in all local networks.
pub fn find_rtsp_streams(rtsp_paths_file: &str) -> Result<ScanReport> {
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
    
    let mut report = ScanReport::new();
    
    for handle in threads {
        if let Ok(res) = handle.join() {
            report.merge(try!(res));
        } else {
            return Err(DiscoveryError::from("port scanner thread panicked"));
        }
    }
    
    // note: we permit only one RTSP service per host (some stupid RTSP servers 
    // are accessible from more than one port and they tend to crash when they 
    // are accessed from the "incorrect" one)
    let rtsp_services   = try!(find_rtsp_services(&report));
    let port_priorities = get_port_priorities(RTSP_PORT_CANDIDATES);
    let rtsp_services   = filter_duplicit_services(
        &rtsp_services,
        &port_priorities);
    
    let rtsp_hosts    = get_hosts(&rtsp_services);
    let http_services = try!(find_http_services(&rtsp_hosts));
    
    let mut threads = Vec::new();
    let paths       = Arc::new(try!(load_rtsp_paths(rtsp_paths_file)));
    
    for (mac, addr) in rtsp_services {
        let paths  = paths.clone();
        let handle = thread::spawn(move || {
            find_rtsp_paths(mac, addr, &paths)
        });
        threads.push(handle);
    }
    
    for handle in threads {
        match handle.join() {
            Err(_) => return Err(DiscoveryError::from(
                "path testing thread panicked")),
            Ok(svc) => report.add_service(try!(svc))
        }
    }
    
    for (mac, saddr) in http_services {
        report.add_service(Service::HTTP(mac, saddr));
    }
    
    Ok(report)
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
    let host = format!("{}", addr.ip());
    let port = addr.port();
    
    // treat connection errors as error responses
    if let Ok(mut client) = RtspClient::new(&host, port) {
        try!(client.set_timeout(Some(1000)));
        let response = client.options();
        Ok(response.is_ok())
    } else {
        Ok(false)
    }
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
    let host = format!("{}", addr.ip());
    let port = addr.port();
    
    let mut client;
    
    // treat connection errors as DESCRIBE errors
    match RtspClient::new(&host, port) {
        Err(_) => return Ok(DescribeStatus::Error),
        Ok(c)  => client = c
    }
    
    try!(client.set_timeout(Some(1000)));
    
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

/// Check if a given service is an HTTP service.
fn is_http_service(addr: SocketAddr) -> Result<bool> {
    let host = format!("{}", addr.ip());
    let port = addr.port();
    
    // treat connection errors as error responses
    if let Ok(mut client) = HttpClient::new(&host, port) {
        try!(client.set_timeout(Some(1000)));
        let response = client.head("/");
        Ok(response.is_ok())
    } else {
        Ok(false)
    }
}

/// Find open ports on all available hosts within a given network and port 
/// range.
fn find_services(
    pc: pcap::ThreadingContext,
    device: &EthernetDevice,
    ports: &PortCollection) -> Result<ScanReport> {
    let mut report  = ScanReport::new();
    
    for (mac, ip) in try!(Ipv4ArpScanner::scan_device(pc.clone(), device)) {
        report.add_host(mac, IpAddr::V4(ip), HINFO_FLAG_ARP);
    }
    
    for (mac, ip) in try!(IcmpScanner::scan_device(pc.clone(), device)) {
        report.add_host(mac, IpAddr::V4(ip), HINFO_FLAG_ICMP);
    }
    
    let open_ports = {
        let hosts = report.hosts()
            .map(|host| (host.mac_addr, host.ip_addr));
        
        try!(find_open_ports(pc, device, hosts, ports))
    };
    
    for (mac, addr) in open_ports {
        report.add_port(mac, addr.ip(), addr.port());
    }
    
    Ok(report)
}

/// Check if any of given TCP ports is open on on any host from a given set.
fn find_open_ports<H: IntoIterator<Item=(MacAddr, IpAddr)>>(
    pc: pcap::ThreadingContext,
    device: &EthernetDevice,
    hosts: H, 
    ports: &PortCollection) -> Result<Vec<(MacAddr, SocketAddr)>> {
    let hosts = hosts.into_iter()
        .filter_map(|(mac, ip)| match ip {
            IpAddr::V4(ip) => Some((mac, ip)),
            _              => None
        });
    
    let res = try!(TcpPortScanner::scan_ipv4_hosts(pc, device, hosts, ports))
        .into_iter()
        .map(|(mac, ip, p)| (mac, SocketAddr::V4(SocketAddrV4::new(ip, p))))
        .collect::<Vec<_>>();
    
    Ok(res)
}

/// Find all RTSP services among a given set of sockets.
fn find_rtsp_services(
    report: &ScanReport) -> Result<Vec<(MacAddr, SocketAddr)>> {
    let mut threads = Vec::new();
    let mut res     = Vec::new();
    
    for (mac, addr) in report.socket_addrs() {
        let handle = thread::spawn(move || {
            (mac, addr, is_rtsp_service(addr))
        });
        threads.push(handle);
    }
    
    for handle in threads {
        if let Ok((mac, addr, rtsp)) = handle.join() {
            if try!(rtsp) {
                res.push((mac, addr));
            }
        } else {
            return Err(DiscoveryError::from("RTSP service testing thread panicked"));
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

/// Find all HTTP services among a given set of sockets.
fn find_http_services(
    hosts: &[(MacAddr, IpAddr)]) -> Result<Vec<(MacAddr, SocketAddr)>> {
    let mut threads = Vec::new();
    let mut res     = Vec::new();
    
    for &(ref mac, ref ip) in hosts {
        let mac  = *mac;
        let addr = match *ip {
            IpAddr::V4(ip) => SocketAddr::V4(SocketAddrV4::new(ip, 80)),
            IpAddr::V6(ip) => SocketAddr::V6(SocketAddrV6::new(ip, 80, 0, 0)),
        };
        
        let handle = thread::spawn(move || {
            (mac, addr, is_http_service(addr))
        });
        
        threads.push(handle);
    }
    
    for handle in threads {
        if let Ok((mac, addr, http)) = handle.join() {
            if try!(http) {
                res.push((mac, addr));
            }
        } else {
            return Err(DiscoveryError::from("HTTP service testing thread panicked"));
        }
    }
    
    Ok(res)
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
    services: &[(MacAddr, SocketAddr)], 
    port_priorities: &HashMap<u16, usize>) -> Vec<(MacAddr, SocketAddr)> {
    let mut svc_map = HashMap::new();
    
    for &(ref mac, ref saddr) in services {
        let mac  = *mac;
        let ip   = saddr.ip();
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
        .map(|(_, (mac, ip, port))| match ip {
            IpAddr::V4(ip) => (mac, SocketAddr::V4(SocketAddrV4::new(ip, port))),
            IpAddr::V6(ip) => (mac, SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
        })
        .collect::<_>()
}

/// Get a list of distinct hosts from a given list of services.
fn get_hosts(services: &[(MacAddr, SocketAddr)]) -> Vec<(MacAddr, IpAddr)> {
    let mut host_map = HashMap::new();
    
    for &(ref mac, ref saddr) in services {
        let ip = saddr.ip();
        host_map.insert(ip, (*mac, ip));
    }
    
    host_map.into_iter()
        .map(|(_, v)| v)
        .collect::<_>()
}

#[cfg(test)]
use std::net::Ipv4Addr;

#[cfg(test)]
#[test]
/// Test the service priority filtering function.
fn test_service_filtering() {
    let ports = [554, 80];
    let mac   = MacAddr::new(0, 0, 0, 0, 0, 0);
    let ip    = Ipv4Addr::new(0, 0, 0, 0);
    
    let mut services = Vec::new();
    
    services.push((mac, SocketAddr::V4(SocketAddrV4::new(ip, 80))));
    services.push((mac, SocketAddr::V4(SocketAddrV4::new(ip, 554))));
    
    let port_priorities = get_port_priorities(&ports);
    let services = filter_duplicit_services(&services, &port_priorities);
    
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].1.port(), 554);
}
