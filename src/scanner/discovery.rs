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
use net::http::ResponseHeader as HttpResponseHeader;
use net::rtsp::Client as RtspClient;
use net::raw::devices::EthernetDevice;
use net::raw::ether::MacAddr;
use net::raw::arp::scanner::Ipv4ArpScanner;
use net::raw::icmp::scanner::IcmpScanner;
use net::raw::tcp::scanner::{TcpPortScanner, PortCollection};
use net::rtsp::sdp::{SessionDescription, MediaType, RTPMap, FromAttribute};

use scanner::result::{
    ScanResult,

    HR_FLAG_ARP,
    HR_FLAG_ICMP,
};

use svc_table::Service;

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
     8554,  7070, 10554,    80,  6667
];

/// HTTP port candidates.
static HTTP_PORT_CANDIDATES: &'static [u16] = &[
       80,    81,  8080,  8081,  8090
];

/// Find all RTSP and MJPEG streams and corresponding HTTP services in all
/// local networks.
pub fn scan_network(
    rtsp_paths_file: &str,
    mjpeg_paths_file: &str) -> Result<ScanResult> {
    let mut port_set = HashSet::<u16>::new();

    port_set.extend(RTSP_PORT_CANDIDATES);
    port_set.extend(HTTP_PORT_CANDIDATES);

    let port_candidates = PortCollection::new()
        .add_all(port_set);

    let mut report = find_all_open_ports(&port_candidates)?;

    // note: we permit only one RTSP service per host (some stupid RTSP servers
    // are accessible from more than one port and they tend to crash when they
    // are accessed from the "incorrect" one)
    let rtsp_ports = find_rtsp_ports(&report, RTSP_PORT_CANDIDATES)?;
    let rtsp_port_priorities = get_port_priorities(RTSP_PORT_CANDIDATES);
    let rtsp_ports = filter_duplicit_services(
        &rtsp_ports,
        &rtsp_port_priorities);

    // note: we permit only one HTTP service per host
    let http_ports = find_http_ports(&report, HTTP_PORT_CANDIDATES)?;
    let http_port_priorities = get_port_priorities(HTTP_PORT_CANDIDATES);
    let http_ports = filter_duplicit_services(
        &http_ports,
        &http_port_priorities);

    let rtsp_services  = find_rtsp_services(rtsp_paths_file, &rtsp_ports)?;
    let mjpeg_services = find_mjpeg_services(mjpeg_paths_file, &http_ports)?;

    let mut hosts = Vec::new();

    hosts.extend(get_hosts(&rtsp_services));
    hosts.extend(get_hosts(&mjpeg_services));

    let http_services = find_http_services(&http_ports, &hosts);

    for svc in rtsp_services {
        report.add_service(svc);
    }

    for svc in mjpeg_services {
        report.add_service(svc);
    }

    for svc in http_services {
        report.add_service(svc);
    }

    Ok(report)
}

/// Load all path variants from a given file.
fn load_paths(file: &str) -> Result<Vec<String>> {
    let file      = File::open(file)?;
    let breader   = BufReader::new(file);
    let mut paths = Vec::new();

    for line in breader.lines() {
        let path = line?;
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
        client.set_timeout(Some(1000))?;
        let response = client.options();
        Ok(response.is_ok())
    } else {
        Ok(false)
    }
}

/// Check if a given session description contains at least one H.264 or
/// a general MPEG4 video stream.
fn is_supported_rtsp_service(sdp: &[u8]) -> bool {
    if let Ok(sdp) = SessionDescription::parse(sdp) {
        let mut vcodecs   = HashSet::new();
        let video_streams = sdp.media_descriptions.into_iter()
            .filter(|md| md.media_type == MediaType::Video);

        for md in video_streams {
            for attr in md.attributes {
                if let Ok(rtpmap) = RTPMap::from_attr(&attr) {
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

/// Get describe status for a given RTSP service and path.
fn get_rtsp_describe_status(
    addr: SocketAddr,
    path: &str) -> Result<DescribeStatus> {
    let host = format!("{}", addr.ip());
    let port = addr.port();

    let mut client;

    // treat connection errors as DESCRIBE errors
    match RtspClient::new(&host, port) {
        Err(_) => return Ok(DescribeStatus::Error),
        Ok(c)  => client = c
    }

    client.set_timeout(Some(1000))?;

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
                200 if is_supported_rtsp_service(&response.body) =>
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
        client.set_timeout(Some(1000))?;
        let response = client.get_header("/");
        Ok(response.is_ok())
    } else {
        Ok(false)
    }
}

/// Get response header for a given HTTP endpoint or None if the header cannot
/// be retreived.
fn get_http_response_header(
    addr: SocketAddr,
    path: &str) -> Result<Option<HttpResponseHeader>> {
    let host = format!("{}", addr.ip());
    let port = addr.port();

    // ignore connection errors
    if let Ok(mut client) = HttpClient::new(&host, port) {
        client.set_timeout(Some(1000))?;
        if let Ok(header) = client.get_header(path) {
            Ok(Some(header))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

/// Find open ports on all available hosts within all local networks accessible
/// directly from this host.
fn find_all_open_ports(ports: &PortCollection) -> Result<ScanResult> {
    let tc      = pcap::new_threading_context();
    let devices = EthernetDevice::list();

    let mut threads = Vec::new();

    for dev in devices {
        let pc     = ports.clone();
        let tc     = tc.clone();
        let handle = thread::spawn(move || {
            find_open_ports_in_network(tc, &dev, &pc)
        });

        threads.push(handle);
    }

    let mut report = ScanResult::new();

    for handle in threads {
        if let Ok(res) = handle.join() {
            report.merge(res?);
        } else {
            return Err(DiscoveryError::from("port scanner thread panicked"));
        }
    }

    Ok(report)
}

/// Find open ports on all available hosts within a given network and port
/// range.
fn find_open_ports_in_network(
    pc: pcap::ThreadingContext,
    device: &EthernetDevice,
    ports: &PortCollection) -> Result<ScanResult> {
    let mut report = ScanResult::new();

    for (mac, ip) in Ipv4ArpScanner::scan_device(pc.clone(), device)? {
        report.add_host(mac, IpAddr::V4(ip), HR_FLAG_ARP);
    }

    for (mac, ip) in IcmpScanner::scan_device(pc.clone(), device)? {
        report.add_host(mac, IpAddr::V4(ip), HR_FLAG_ICMP);
    }

    let open_ports = {
        let hosts = report.hosts()
            .map(|host| (host.mac, host.ip));

        find_open_ports(pc, device, hosts, ports)?
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

    let res = TcpPortScanner::scan_ipv4_hosts(pc, device, hosts, ports)?
        .into_iter()
        .map(|(mac, ip, p)| (mac, SocketAddr::V4(SocketAddrV4::new(ip, p))))
        .collect::<Vec<_>>();

    Ok(res)
}

/// Find all RTSP services.
fn find_rtsp_ports(
    report: &ScanResult,
    rtsp_ports: &[u16]) -> Result<Vec<(MacAddr, SocketAddr)>> {
    let mut ports   = HashSet::<u16>::new();
    let mut threads = Vec::new();
    let mut res     = Vec::new();

    ports.extend(rtsp_ports);

    for (mac, addr) in report.socket_addrs() {
        if ports.contains(&addr.port()) {
            let handle = thread::spawn(move || {
                (mac, addr, is_rtsp_service(addr))
            });
            threads.push(handle);
        }
    }

    for handle in threads {
        if let Ok((mac, addr, rtsp)) = handle.join() {
            if rtsp? {
                res.push((mac, addr));
            }
        } else {
            return Err(DiscoveryError::from("RTSP service testing thread panicked"));
        }
    }

    Ok(res)
}

/// Find the first available RTSP path for a given RTSP service.
fn find_rtsp_path(
    mac: MacAddr,
    addr: SocketAddr,
    paths: &[String]) -> Result<Service> {
    let mut service = Service::unknown_rtsp(mac, addr);

    for path in paths {
        let status = get_rtsp_describe_status(addr, path)?;
        if status == DescribeStatus::Ok {
            service = Service::rtsp(mac, addr, path.to_string());
        } else if status == DescribeStatus::Unsupported {
            service = Service::unsupported_rtsp(mac, addr, path.to_string());
        } else if status == DescribeStatus::Locked {
            service = Service::locked_rtsp(mac, addr, None);
        }

        match status {
            DescribeStatus::Ok     => break,
            DescribeStatus::Locked => break,
            _ => ()
        }
    }

    Ok(service)
}

/// Find all RTSP services.
fn find_rtsp_services(
    rtsp_paths_file: &str,
    rtsp_ports: &[(MacAddr, SocketAddr)]) -> Result<Vec<Service>> {
    let paths = Arc::new(load_paths(rtsp_paths_file)?);

    let mut threads = Vec::new();
    let mut res     = Vec::new();

    for &(ref mac, ref saddr) in rtsp_ports {
        let mac    = *mac;
        let saddr  = *saddr;
        let paths  = paths.clone();
        let handle = thread::spawn(move || {
            find_rtsp_path(mac, saddr, &paths)
        });
        threads.push(handle);
    }

    for handle in threads {
        match handle.join() {
            Err(_) => return Err(DiscoveryError::from(
                "RTSP path testing thread panicked")),
            Ok(svc) => res.push(svc?)
        }
    }

    Ok(res)
}

/// Find all HTTP services.
fn find_http_ports(
    report: &ScanResult,
    http_ports: &[u16]) -> Result<Vec<(MacAddr, SocketAddr)>> {
    let mut ports   = HashSet::<u16>::new();
    let mut threads = Vec::new();
    let mut res     = Vec::new();

    ports.extend(http_ports);

    for (mac, addr) in report.socket_addrs() {
        if ports.contains(&addr.port()) {
            let handle = thread::spawn(move || {
                (mac, addr, is_http_service(addr))
            });
            threads.push(handle);
        }
    }

    for handle in threads {
        if let Ok((mac, addr, http)) = handle.join() {
            if http? {
                res.push((mac, addr));
            }
        } else {
            return Err(DiscoveryError::from("HTTP service testing thread panicked"));
        }
    }

    Ok(res)
}

/// Find the first available MJPEG path for a given HTTP service.
fn find_mjpeg_path(
    mac: MacAddr,
    addr: SocketAddr,
    paths: &[String]) -> Result<Option<Service>> {
    for path in paths {
        if let Some(header) = get_http_response_header(addr, path)? {
            if header.code == 200 {
                let ctype = header.get_str("content-type")
                    .unwrap_or("")
                    .to_lowercase();

                if  ctype.starts_with("image/jpeg") ||
                    ctype.starts_with("multipart/x-mixed-replace") {
                    return Ok(Some(Service::mjpeg(mac, addr, path.to_string())));
                }
            } else if header.code == 401 {
                return Ok(Some(Service::locked_mjpeg(mac, addr, None)));
            }
        }
    }

    Ok(None)
}

/// Find all MJPEG services.
fn find_mjpeg_services(
    mjpeg_paths_file: &str,
    mjpeg_ports: &[(MacAddr, SocketAddr)]) -> Result<Vec<Service>> {
    let paths = Arc::new(load_paths(mjpeg_paths_file)?);

    let mut threads = Vec::new();
    let mut res     = Vec::new();

    for &(ref mac, ref saddr) in mjpeg_ports {
        let mac    = *mac;
        let saddr  = *saddr;
        let paths  = paths.clone();
        let handle = thread::spawn(move || {
            find_mjpeg_path(mac, saddr, &paths)
        });
        threads.push(handle);
    }

    for handle in threads {
        match handle.join() {
            Err(_) => return Err(DiscoveryError::from(
                "MJPEG path testing thread panicked")),
            Ok(svc) => if let Some(svc) = svc? {
                res.push(svc)
            }
        }
    }

    Ok(res)
}

/// Return all http services on given hosts.
fn find_http_services(
    http_ports: &[(MacAddr, SocketAddr)],
    hosts: &[IpAddr]) -> Vec<Service> {
    let mut host_set = HashSet::<IpAddr>::new();
    let mut res      = Vec::new();

    host_set.extend(hosts);

    for &(ref mac, ref saddr) in http_ports {
        if host_set.contains(&saddr.ip()) {
            res.push(Service::http(*mac, *saddr));
        }
    }

    res
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
fn get_hosts(services: &[Service]) -> Vec<IpAddr> {
    let mut hosts = HashSet::new();

    for svc in services {
        if let Some(saddr) = svc.address() {
            hosts.insert(saddr.ip());
        }
    }

    hosts.into_iter()
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
