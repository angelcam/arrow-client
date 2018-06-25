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
use std::result;

use std::fs::File;
use std::error::Error;
use std::collections::{HashMap, HashSet};
use std::io::{BufReader, BufRead};
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::future;
use futures::stream;

use futures::{Future, Poll, Stream};

use tokio;

use net::raw::pcap;

use net::http::Request as HttpRequest;
use net::http::Response as HttpResponse;
use net::rtsp::Request as RtspRequest;
use net::rtsp::Response as RtspResponse;
use net::rtsp::sdp::{SessionDescription, MediaType, RTPMap, FromAttribute};
use net::raw::arp::scanner::Ipv4ArpScanner;
use net::raw::devices::EthernetDevice;
use net::raw::ether::MacAddr;
use net::raw::icmp::scanner::IcmpScanner;
use net::raw::tcp::scanner::{TcpPortScanner, PortCollection};

use scanner::result::{
    ScanResult,

    HR_FLAG_ARP,
    HR_FLAG_ICMP,
};

use svc_table::{Service, ServiceType};

use utils::logger::{BoxLogger, Logger};

/// RTSP port candidates.
static RTSP_PORT_CANDIDATES: &'static [u16] = &[
      554,    88,    81,   555,  7447,
     8554,  7070, 10554,    80,  6667
];

/// HTTP port candidates.
static HTTP_PORT_CANDIDATES: &'static [u16] = &[
       80,    81,  8080,  8081,  8090
];

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

/// Scan all local networks for RTSP and MJPEG streams and associated HTTP
/// services.
pub fn scan_network(
    logger: BoxLogger,
    rtsp_paths_file: &str,
    mjpeg_paths_file: &str) -> Result<ScanResult> {
    let mut runtime = tokio::runtime::current_thread::Runtime::new()
        .map_err(|err| DiscoveryError::from(
            format!("Asyn IO error: {}", err)
        ))?;

    let context = Context::new(
        logger.clone(),
        rtsp_paths_file,
        mjpeg_paths_file)?;

    let rtsp_port_priorities = context.get_rtsp_port_priorities();
    let http_port_priorities = context.get_http_port_priorities();

    let mut report = find_open_ports(context.clone());

    let rtsp_services = runtime.block_on(
        find_rtsp_services(
            context.clone(),
            report.socket_addrs()))?;

    let rtsp_services = filter_duplicit_services(
        rtsp_services,
        rtsp_port_priorities);

    let rtsp_streams = runtime.block_on(
        find_rtsp_streams(
            context.clone(),
            rtsp_services.into_iter()))?;

    let http_services = runtime.block_on(
        find_http_services(
            context.clone(),
            report.socket_addrs()))?;

    let http_services = filter_duplicit_services(
            http_services,
            http_port_priorities);

    let mjpeg_services = http_services.clone();

    let mjpeg_streams = runtime.block_on(
        find_mjpeg_streams(
            context.clone(),
            mjpeg_services.into_iter()))?;

    let mut hosts = HashSet::new();

    hosts.extend(get_hosts(&rtsp_streams));
    hosts.extend(get_hosts(&mjpeg_streams));

    let http_services = http_services.into_iter()
        .filter_map(|(mac, saddr)| {
            if hosts.contains(&saddr.ip()) {
                Some(Service::http(mac, saddr))
            } else {
                None
            }
        });

    for svc in rtsp_streams {
        report.add_service(svc);
    }

    for svc in mjpeg_streams {
        report.add_service(svc);
    }

    for svc in http_services {
        report.add_service(svc);
    }

    Ok(report)
}

/// Internal data for the network scanner context.
struct ContextData {
    logger:               BoxLogger,
    port_candidates:      HashSet<u16>,
    rtsp_port_candidates: HashSet<u16>,
    http_port_candidates: HashSet<u16>,
    rtsp_port_priorities: HashMap<u16, usize>,
    http_port_priorities: HashMap<u16, usize>,
    rtsp_paths:           Arc<Vec<String>>,
    mjpeg_paths:          Arc<Vec<String>>,
    request_timeout:      Duration,
}

impl ContextData {
    /// Create new context data for the network scanner context.
    fn new(
        logger: BoxLogger,
        rtsp_paths_file: &str,
        mjpeg_paths_file: &str) -> Result<ContextData> {
        let rtsp_paths  = load_paths(rtsp_paths_file)?;
        let mjpeg_paths = load_paths(mjpeg_paths_file)?;

        let mut port_candidates = HashSet::<u16>::new();
        let mut rtsp_port_candidates = HashSet::<u16>::new();
        let mut http_port_candidates = HashSet::<u16>::new();

        port_candidates.extend(RTSP_PORT_CANDIDATES);
        port_candidates.extend(HTTP_PORT_CANDIDATES);

        rtsp_port_candidates.extend(RTSP_PORT_CANDIDATES);
        http_port_candidates.extend(HTTP_PORT_CANDIDATES);

        let rtsp_port_priorities = get_port_priorities(RTSP_PORT_CANDIDATES);
        let http_port_priorities = get_port_priorities(HTTP_PORT_CANDIDATES);

        let cdata = ContextData {
            logger: logger,
            port_candidates: port_candidates,
            rtsp_port_candidates: rtsp_port_candidates,
            http_port_candidates: http_port_candidates,
            rtsp_port_priorities: rtsp_port_priorities,
            http_port_priorities: http_port_priorities,
            rtsp_paths:           Arc::new(rtsp_paths),
            mjpeg_paths:          Arc::new(mjpeg_paths),
            request_timeout:      Duration::from_millis(2000),
        };

        Ok(cdata)
    }
}

/// Helper function for loading all path variants from a given file.
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

/// Helper function for constructing a map of port priorities. Assuming the
/// given list of ports is sorted according to port priority (from highest to
/// lowest), get a map of port -> port_priority pairs.
fn get_port_priorities(ports: &[u16]) -> HashMap<u16, usize> {
    let mut res = HashMap::new();

    let len = ports.len();

    for i in 0..len {
        res.insert(ports[i], len - i);
    }

    res
}

/// Network scanner context.
#[derive(Clone)]
struct Context {
    data: Arc<ContextData>,
}

impl Context {
    /// Create a new network scanner context.
    fn new(
        logger: BoxLogger,
        rtsp_paths_file: &str,
        mjpeg_paths_file: &str) -> Result<Context> {
        let data = ContextData::new(
            logger,
            rtsp_paths_file,
            mjpeg_paths_file)?;

        let context = Context {
            data: Arc::new(data),
        };

        Ok(context)
    }

    /// Get logger.
    fn get_logger(&self) -> BoxLogger {
        self.data.logger.clone()
    }

    /// Get request timeout.
    fn get_request_timeout(&self) -> Duration {
        self.data.request_timeout.clone()
    }

    /// Get all port candidates.
    fn get_port_candidates(&self) -> &HashSet<u16> {
        &self.data.port_candidates
    }

    /// Check if a given port is an RTSP port candidate.
    fn is_rtsp_port_candidate(&self, port: u16) -> bool {
        self.data.rtsp_port_candidates.contains(&port)
    }

    /// Check if a given port is an HTTP port candidate.
    fn is_http_port_candidate(&self, port: u16) -> bool {
        self.data.http_port_candidates.contains(&port)
    }

    /// Get RTSP port priorities.
    fn get_rtsp_port_priorities(&self) -> &HashMap<u16, usize> {
        &self.data.rtsp_port_priorities
    }

    /// Get HTTP port priorities.
    fn get_http_port_priorities(&self) -> &HashMap<u16, usize> {
        &self.data.http_port_priorities
    }

    /// Get RTSP paths.
    fn get_rtsp_paths(&self) -> Arc<Vec<String>> {
        self.data.rtsp_paths.clone()
    }

    /// Get MJPEG paths.
    fn get_mjpeg_paths(&self) -> Arc<Vec<String>> {
        self.data.mjpeg_paths.clone()
    }
}

/// Find open ports on all available hosts within all local networks
/// accessible directly from this host.
fn find_open_ports(scanner: Context) -> ScanResult {
    let mut logger = scanner.get_logger();

    let mut report = ScanResult::new();

    let devices = EthernetDevice::list();

    for dev in devices {
        let res = find_open_ports_in_network(scanner.clone(), &dev);

        if let Err(err) = res {
            log_warn!(&mut logger, "unable to find open ports in local network on interface {}: {}", dev.name, err);
        } else if let Ok(res) = res {
            report.merge(res);
        }
    }

    report
}

/// Find open ports on all available hosts within a given network.
fn find_open_ports_in_network(
    context: Context,
    device: &EthernetDevice) -> Result<ScanResult> {
    let mut logger = context.get_logger();

    let mut report = ScanResult::new();

    log_debug!(&mut logger, "running ARP scan in local network on interface {}", device.name);
    for (mac, ip) in Ipv4ArpScanner::scan_device(device)? {
        report.add_host(mac, IpAddr::V4(ip), HR_FLAG_ARP);
    }

    log_debug!(&mut logger, "running ICMP echo scan in local network on interface {}", device.name);
    for (mac, ip) in IcmpScanner::scan_device(device)? {
        report.add_host(mac, IpAddr::V4(ip), HR_FLAG_ICMP);
    }

    let open_ports;

    {
        let hosts = report.hosts()
            .map(|host| (host.mac, host.ip));

        open_ports = find_open_ports_on_hosts(context, device, hosts)?;
    }

    for (mac, addr) in open_ports {
        report.add_port(mac, addr.ip(), addr.port());
    }

    Ok(report)
}

/// Find open ports on given hosts from a given network.
fn find_open_ports_on_hosts<I>(
    context: Context,
    device: &EthernetDevice,
    hosts: I) -> Result<Vec<(MacAddr, SocketAddr)>>
    where I: IntoIterator<Item=(MacAddr, IpAddr)> {
    let mut logger = context.get_logger();

    log_debug!(&mut logger, "running TCP port scan in local network on interface {}", device.name);

    let hosts = hosts.into_iter()
        .filter_map(|(mac, ip)| match ip {
            IpAddr::V4(ip) => Some((mac, ip)),
            _              => None
        });

    let candidates = context.get_port_candidates()
        .iter()
        .map(|port| *port);

    let ports = PortCollection::new()
        .add_all(candidates);

    let res = TcpPortScanner::scan_ipv4_hosts(device, hosts, &ports)?
        .into_iter()
        .map(|(mac, ip, p)| (mac, SocketAddr::V4(SocketAddrV4::new(ip, p))))
        .collect::<Vec<_>>();

    Ok(res)
}

/// Wrapper around a boxed future.
struct FutureResult<T> {
    inner: Box<Future<Item=T, Error=DiscoveryError>>,
}

impl<T> FutureResult<T> {
    /// Create a new future result from a given future.
    fn new<F>(fut: F) -> FutureResult<T>
        where F: 'static + Future<Item=T, Error=DiscoveryError> {
        FutureResult {
            inner: Box::new(fut),
        }
    }
}

impl<T> Future for FutureResult<T> {
    type Item = T;
    type Error = DiscoveryError;

    fn poll(&mut self) -> Poll<T, DiscoveryError> {
        self.inner.poll()
    }
}

impl<T> From<Result<T>> for FutureResult<T>
    where T: 'static {
    fn from(result: Result<T>) -> FutureResult<T> {
        FutureResult::new(future::result(result))
    }
}

/// Stream type.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum StreamType {
    Supported,
    Locked,
    Unsupported,
    NotFound,
    Error
}

impl From<RtspResponse> for StreamType {
    fn from(response: RtspResponse) -> StreamType {
        let status_code = response.status_code();

        if status_code == 200 {
             if is_supported_rtsp_service(response.body()) {
                StreamType::Supported
            } else {
                StreamType::Unsupported
            }
        } else if status_code == 401 {
            StreamType::Locked
        } else if status_code == 404 {
            StreamType::NotFound
        } else {
            StreamType::Error
        }
    }
}

impl From<HttpResponse> for StreamType {
    fn from(response: HttpResponse) -> StreamType {
        let status_code = response.status_code();

        if status_code == 200 {
            if is_supported_mjpeg_service(&response) {
                    StreamType::Supported
            } else {
                StreamType::Unsupported
            }
        } else if status_code == 401 {
            StreamType::Locked
        } else if status_code == 404 {
            StreamType::NotFound
        } else {
            StreamType::Error
        }
    }
}

/// Check if a given session description contains at least one H.264 or
/// a general MPEG4 video stream.
fn is_supported_rtsp_service(sdp: &[u8]) -> bool {
    if let Ok(sdp) = SessionDescription::parse(sdp) {
        let mut vcodecs = HashSet::new();

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

/// Check if a given HTTP response can be interpreted as an MJPEG stream.
fn is_supported_mjpeg_service(response: &HttpResponse) -> bool {
    let ctype = response.get_header_field_value("content-type")
        .unwrap_or("")
        .to_lowercase();

    ctype.starts_with("multipart/x-mixed-replace") ||
        ctype.starts_with("image/jpeg") ||
        ctype.starts_with("image/jpg")
}

/// Check if a given service is an RTSP service.
fn is_rtsp_service(context: Context, addr: SocketAddr) -> FutureResult<bool> {
    let request = RtspRequest::options(&format!("rtsp://{}/", addr));

    if request.is_err() {
        return FutureResult::from(Ok(false));
    }

    let check = request.unwrap()
        .set_request_timeout(Some(context.get_request_timeout()))
        .send()
        .then(|result| {
            Ok(result.is_ok())
        });

    FutureResult::new(check)
}

/// Check if a given service is an HTTP service.
fn is_http_service(context: Context, addr: SocketAddr) -> FutureResult<bool> {
    let check = get_http_response(context, addr, "/")
        .then(|result| {
            Ok(result.is_ok())
        });

    FutureResult::new(check)
}

/// Get HTTP response for a given path from a given HTTP server.
fn get_http_response(
    context: Context,
    addr: SocketAddr,
    path: &str) -> FutureResult<HttpResponse> {
    let request = HttpRequest::get_header(&format!("http://{}{}", addr, path))
        .map_err(|err| DiscoveryError::from(
            format!("HTTP client error: {}", err)
        ));

    if let Err(err) = request {
        return FutureResult::from(Err(err));
    }

    let response = request.unwrap()
        .set_request_timeout(Some(context.get_request_timeout()))
        .send()
        .map_err(|err| DiscoveryError::from(
            format!("HTTP client error: {}", err)
        ));

    FutureResult::new(response)
}

/// Find all RTSP services.
fn find_rtsp_services<I>(
    context: Context,
    open_ports: I) -> FutureResult<Vec<(MacAddr, SocketAddr)>>
    where I: IntoIterator<Item=(MacAddr, SocketAddr)> {
    let mut logger = context.get_logger();

    log_debug!(&mut logger, "looking for RTSP services");

    filter_services(
        context.clone(),
        open_ports,
        |context, saddr| {
            if context.is_rtsp_port_candidate(saddr.port()) {
                is_rtsp_service(context, saddr)
            } else {
                FutureResult::from(Ok(false))
            }
    })
}

/// Find all HTTP services.
fn find_http_services<I>(
    context: Context,
    open_ports: I) -> FutureResult<Vec<(MacAddr, SocketAddr)>>
    where I: IntoIterator<Item=(MacAddr, SocketAddr)> {
    let mut logger = context.get_logger();

    log_debug!(&mut logger, "looking for HTTP services");

    filter_services(
        context.clone(),
        open_ports,
        |context, saddr| {
            if context.is_http_port_candidate(saddr.port()) {
                is_http_service(context, saddr)
            } else {
                FutureResult::from(Ok(false))
            }
    })
}

/// Filter a given list of services using a given async predicate.
fn filter_services<I, P>(
    context: Context,
    candidates: I,
    predicate: P) -> FutureResult<Vec<(MacAddr, SocketAddr)>>
    where I: IntoIterator<Item=(MacAddr, SocketAddr)>,
          P: Fn(Context, SocketAddr) -> FutureResult<bool> {
    let futures = candidates.into_iter()
        .map(|(mac, saddr)| {
            predicate(context.clone(), saddr)
                .then(move |res| match res {
                    Ok(res) => Ok((mac, saddr, res)),
                    Err(_)  => Ok((mac, saddr, false)),
                })
        });

    let filtered = stream::futures_unordered(futures)
        .filter_map(|(mac, saddr, res)| {
            if res {
                Some((mac, saddr))
            } else {
                None
            }
        })
        .collect();

    FutureResult::new(filtered)
}

/// Filter out duplicit services from a given list using given priorities.
fn filter_duplicit_services<I>(
    services: I,
    port_priorities: &HashMap<u16, usize>) -> Vec<(MacAddr, SocketAddr)>
    where I: IntoIterator<Item=(MacAddr, SocketAddr)> {
    let mut svc_map = HashMap::new();

    for (mac, saddr) in services {
        let ip   = saddr.ip();
        let port = saddr.port();

        if svc_map.contains_key(&ip) {
            let old_port = svc_map.get(&ip)
                .map(|&(_, _, port)| port)
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

/// Find all RTSP streams.
fn find_rtsp_streams<I>(
    context: Context,
    rtsp_services: I) -> FutureResult<Vec<Service>>
    where I: IntoIterator<Item=(MacAddr, SocketAddr)> {
    let mut logger = context.get_logger();

    log_debug!(&mut logger, "looking for RTSP streams");

    let futures = rtsp_services.into_iter()
        .map(|(mac, addr)| {
            find_rtsp_stream(context.clone(), mac, addr)
        });

    let streams = stream::futures_unordered(futures);

    FutureResult::new(streams.collect())
}

/// Find the first available RTSP stream for a given RTSP service.
fn find_rtsp_stream(
    context: Context,
    mac: MacAddr,
    addr: SocketAddr) -> FutureResult<Service> {
    let paths = context.get_rtsp_paths();

    let result = Arc::new(Mutex::new(Service::unknown_rtsp(mac, addr)));

    let accumulator = Arc::downgrade(&result);

    let stream = stream::iter_ok::<_, DiscoveryError>(0..paths.len())
        .and_then(move |index| match paths.get(index) {
            Some(path) => get_rtsp_stream(context.clone(), mac, addr, path),
            None       => FutureResult::from(Ok(None)),
        })
        .filter_map(|svc| svc)
        .skip_while(move |svc| {
            if let Some(result) = accumulator.upgrade() {
                *result.lock().unwrap() = svc.clone();
            }

            match svc.service_type() {
                ServiceType::RTSP       => Ok(false),
                ServiceType::LockedRTSP => Ok(false),
                _ => Ok(true),
            }
        })
        .into_future()
        .and_then(move |_| {
            if let Ok(result) = Arc::try_unwrap(result) {
                Ok(result.into_inner().unwrap())
            } else {
                Ok(Service::unknown_rtsp(mac, addr))
            }
        })
        .or_else(move |_| {
            Ok(Service::unknown_rtsp(mac, addr))
        });

    FutureResult::new(stream)
}

/// Get RTSP stream or None for a given RTSP service and path.
fn get_rtsp_stream(
    context: Context,
    mac: MacAddr,
    addr: SocketAddr,
    path: &str) -> FutureResult<Option<Service>> {
    let path = path.to_string();

    let service = get_rtsp_stream_type(context, addr, &path)
        .map(move |status| match status {
            StreamType::Supported =>
                Some(Service::rtsp(mac, addr, path)),
            StreamType::Unsupported =>
                Some(Service::unsupported_rtsp(mac, addr, path)),
            StreamType::Locked =>
                Some(Service::locked_rtsp(mac, addr, None)),

            _ => None
        });

    FutureResult::new(service)
}

/// Get stream type for a given RTSP service and path.
fn get_rtsp_stream_type(
    context: Context,
    addr: SocketAddr,
    path: &str) -> FutureResult<StreamType> {
    let path = path.to_string();

    let request = RtspRequest::describe(&format!("rtsp://{}{}", addr, path));

    if request.is_err() {
        return FutureResult::from(Ok(StreamType::Error));
    }

    let status = request.unwrap()
        .set_request_timeout(Some(context.get_request_timeout()))
        .send()
        .and_then(move |response| {
            if is_hipcam_rtsp_response(&response)
                && path != "/11" && path != "/12" {
                Ok(StreamType::NotFound)
            } else {
                Ok(StreamType::from(response))
            }
        })
        .or_else(|_| {
            Ok(StreamType::Error)
        });

    FutureResult::new(status)
}

/// Check if a given RTSP response is from a buggy Hi(I)pcam RTSP server.
fn is_hipcam_rtsp_response(response: &RtspResponse) -> bool {
    match response.get_header_field_value("server") {
        Some("HiIpcam/V100R003 VodServer/1.0.0") => true,
        Some("Hipcam RealServer/V1.0")           => true,
        _ => false,
    }
}

/// Find all MJPEG streams.
fn find_mjpeg_streams<I>(
    context: Context,
    mjpeg_services: I) -> FutureResult<Vec<Service>>
    where I: IntoIterator<Item=(MacAddr, SocketAddr)> {
    let mut logger = context.get_logger();

    log_debug!(&mut logger, "looking for MJPEG streams");

    let futures = mjpeg_services.into_iter()
        .map(|(mac, addr)| {
            find_mjpeg_path(context.clone(), mac, addr)
        });

    let streams = stream::futures_unordered(futures)
        .filter_map(|svc| svc);

    FutureResult::new(streams.collect())
}

/// Find the first available MJPEG stream for a given HTTP service.
fn find_mjpeg_path(
    context: Context,
    mac: MacAddr,
    addr: SocketAddr) -> FutureResult<Option<Service>> {
    let paths = context.get_mjpeg_paths();

    let stream = stream::iter_ok::<_, DiscoveryError>(0..paths.len())
        .and_then(move |index| match paths.get(index) {
            Some(path) => get_mjpeg_stream(context.clone(), mac, addr, path),
            None       => FutureResult::from(Ok(None)),
        })
        .filter_map(|svc| svc)
        .into_future()
        .and_then(|(svc, _)| {
            Ok(svc)
        })
        .or_else(|_| {
            Ok(None)
        });

    FutureResult::new(stream)
}

/// Get MJPEG stream or None for a given HTTP service and path.
fn get_mjpeg_stream(
    context: Context,
    mac: MacAddr,
    addr: SocketAddr,
    path: &str) -> FutureResult<Option<Service>> {
    let path = path.to_string();

    let service = get_http_response(context, addr, &path)
        .map(move |response| match StreamType::from(response) {
            StreamType::Supported =>
                Some(Service::mjpeg(mac, addr, path)),
            StreamType::Locked =>
                Some(Service::locked_mjpeg(mac, addr, None)),

            _ => None
        })
        .or_else(|_| {
            Ok(None)
        });

    FutureResult::new(service)
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

    let services = filter_duplicit_services(services, &port_priorities);

    assert_eq!(services.len(), 1);
    assert_eq!(services[0].1.port(), 554);
}
