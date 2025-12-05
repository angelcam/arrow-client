// Copyright 2025 Angelcam, Inc.
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

//! Network scanner for RTSP streams.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
    time::Duration,
};

use futures::FutureExt;

use crate::{
    error::Error,
    net::{
        http::{Request as HttpRequest, Response as HttpResponse},
        raw::{
            arp::scanner::Ipv4ArpScanner,
            devices::EthernetDevice,
            ether::MacAddr,
            icmp::scanner::IcmpScanner,
            tcp::scanner::{PortCollection, TcpPortScanner},
        },
        rtsp::{
            Request as RtspRequest, Response as RtspResponse,
            sdp::{FromAttribute, MediaType, RTPMap, SessionDescription},
        },
    },
    scanner::result::{HostRecord, ScanResult},
    svc_table::{Service, ServiceType},
};

/// RTSP port candidates.
static RTSP_PORT_CANDIDATES: &[u16] = &[554, 88, 81, 555, 7447, 8554, 7070, 10554, 80, 6667];

/// HTTP port candidates.
static HTTP_PORT_CANDIDATES: &[u16] = &[80, 81, 8080, 8081, 8090];

/// Discovery result type alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Scan all local networks for RTSP and MJPEG streams and associated HTTP
/// services.
pub fn scan_network(
    discovery_whitelist: Arc<Vec<String>>,
    rtsp_paths: Arc<Vec<String>>,
    mjpeg_paths: Arc<Vec<String>>,
) -> Result<ScanResult> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|err| Error::from_static_msg_and_cause("Async IO error", err))?;

    let context = Context::new(discovery_whitelist, rtsp_paths, mjpeg_paths);

    let rtsp_port_priorities = context.get_rtsp_port_priorities();
    let http_port_priorities = context.get_http_port_priorities();

    let mut report = find_open_ports(context.clone());

    let rtsp_services =
        runtime.block_on(find_rtsp_services(context.clone(), report.socket_addrs()));

    let rtsp_services = filter_duplicit_services(rtsp_services, rtsp_port_priorities);

    let rtsp_streams = runtime.block_on(find_rtsp_streams(context.clone(), rtsp_services.clone()));

    let http_services =
        runtime.block_on(find_http_services(context.clone(), report.socket_addrs()));

    let http_services = filter_duplicit_services(http_services, http_port_priorities);

    let mjpeg_streams = runtime.block_on(find_mjpeg_streams(context, http_services.clone()));

    for svc in rtsp_streams {
        report.add_service(svc);
    }

    for (mac, saddr) in rtsp_services {
        report.add_service(Service::tcp(mac, saddr));
    }

    for svc in mjpeg_streams {
        report.add_service(svc);
    }

    for (mac, saddr) in http_services {
        report.add_service(Service::http(mac, saddr));
    }

    Ok(report)
}

/// Internal data for the network scanner context.
struct ContextData {
    port_candidates: HashSet<u16>,
    rtsp_port_candidates: HashSet<u16>,
    http_port_candidates: HashSet<u16>,
    rtsp_port_priorities: HashMap<u16, usize>,
    http_port_priorities: HashMap<u16, usize>,
    discovery_whitelist: Arc<Vec<String>>,
    rtsp_paths: Arc<Vec<String>>,
    mjpeg_paths: Arc<Vec<String>>,
    request_timeout: Duration,
}

impl ContextData {
    /// Create new context data for the network scanner context.
    fn new(
        discovery_whitelist: Arc<Vec<String>>,
        rtsp_paths: Arc<Vec<String>>,
        mjpeg_paths: Arc<Vec<String>>,
    ) -> Self {
        let mut port_candidates = HashSet::<u16>::new();
        let mut rtsp_port_candidates = HashSet::<u16>::new();
        let mut http_port_candidates = HashSet::<u16>::new();

        port_candidates.extend(RTSP_PORT_CANDIDATES);
        port_candidates.extend(HTTP_PORT_CANDIDATES);

        rtsp_port_candidates.extend(RTSP_PORT_CANDIDATES);
        http_port_candidates.extend(HTTP_PORT_CANDIDATES);

        let rtsp_port_priorities = get_port_priorities(RTSP_PORT_CANDIDATES);
        let http_port_priorities = get_port_priorities(HTTP_PORT_CANDIDATES);

        Self {
            port_candidates,
            rtsp_port_candidates,
            http_port_candidates,
            rtsp_port_priorities,
            http_port_priorities,
            discovery_whitelist,
            rtsp_paths,
            mjpeg_paths,
            request_timeout: Duration::from_millis(2000),
        }
    }
}

/// Helper function for constructing a map of port priorities. Assuming the
/// given list of ports is sorted according to port priority (from highest to
/// lowest), get a map of port -> port_priority pairs.
fn get_port_priorities(ports: &[u16]) -> HashMap<u16, usize> {
    let mut res = HashMap::new();

    let len = ports.len();

    for (index, port) in ports.iter().enumerate() {
        res.insert(*port, len - index);
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
        discovery_whitelist: Arc<Vec<String>>,
        rtsp_paths: Arc<Vec<String>>,
        mjpeg_paths: Arc<Vec<String>>,
    ) -> Self {
        Self {
            data: Arc::new(ContextData::new(
                discovery_whitelist,
                rtsp_paths,
                mjpeg_paths,
            )),
        }
    }

    /// Get request timeout.
    fn get_request_timeout(&self) -> Duration {
        self.data.request_timeout
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

    /// Get discovery whitelist.
    fn get_discovery_whitelist(&self) -> Arc<Vec<String>> {
        self.data.discovery_whitelist.clone()
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
    let discovery_whitelist = scanner.get_discovery_whitelist();

    let mut report = ScanResult::new();

    let devices = EthernetDevice::list();

    for dev in devices {
        let name = dev.name();

        let is_whitelisted = discovery_whitelist
            .binary_search_by_key(&name, String::as_str)
            .is_ok();

        if is_whitelisted || discovery_whitelist.is_empty() {
            let res = find_open_ports_in_network(scanner.clone(), &dev);

            if let Err(err) = res {
                warn!("unable to find open ports in local network on interface {name}: {err}");
            } else if let Ok(res) = res {
                report.merge(res);
            }
        }
    }

    report
}

/// Find open ports on all available hosts within a given network.
fn find_open_ports_in_network(context: Context, device: &EthernetDevice) -> Result<ScanResult> {
    let mut report = ScanResult::new();

    debug!(
        "running ARP scan in local network on interface {}",
        device.name()
    );

    for (mac, ip) in Ipv4ArpScanner::scan_device(device)? {
        report.add_host(mac, IpAddr::V4(ip), HostRecord::FLAG_ARP);
    }

    debug!(
        "running ICMP echo scan in local network on interface {}",
        device.name()
    );

    for (mac, ip) in IcmpScanner::scan_device(device)? {
        report.add_host(mac, IpAddr::V4(ip), HostRecord::FLAG_ICMP);
    }

    let open_ports;

    {
        let hosts = report.hosts().map(|host| (host.mac, host.ip));

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
    hosts: I,
) -> Result<Vec<(MacAddr, SocketAddr)>>
where
    I: IntoIterator<Item = (MacAddr, IpAddr)>,
{
    debug!(
        "running TCP port scan in local network on interface {}",
        device.name()
    );

    let hosts = hosts.into_iter().filter_map(|(mac, ip)| match ip {
        IpAddr::V4(ip) => Some((mac, ip)),
        _ => None,
    });

    let candidates = context.get_port_candidates().iter().cloned();

    let ports = PortCollection::new().push_all(candidates);

    let res = TcpPortScanner::scan_ipv4_hosts(device, hosts, &ports)?
        .into_iter()
        .map(|(mac, ip, p)| (mac, SocketAddr::V4(SocketAddrV4::new(ip, p))))
        .collect::<Vec<_>>();

    Ok(res)
}

/// Stream type.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum StreamType {
    Supported,
    Locked,
    Unsupported,
    NotFound,
    Error,
}

impl From<RtspResponse> for StreamType {
    fn from(response: RtspResponse) -> Self {
        let status_code = response.status_code();

        if status_code == 200 {
            if is_supported_rtsp_service(response.body()) {
                Self::Supported
            } else {
                Self::Unsupported
            }
        } else if status_code == 401 {
            Self::Locked
        } else if status_code == 404 {
            Self::NotFound
        } else {
            Self::Error
        }
    }
}

impl From<HttpResponse> for StreamType {
    fn from(response: HttpResponse) -> Self {
        let status_code = response.status_code();

        if status_code == 200 {
            if is_supported_mjpeg_service(&response) {
                Self::Supported
            } else {
                Self::Unsupported
            }
        } else if status_code == 401 {
            Self::Locked
        } else if status_code == 404 {
            Self::NotFound
        } else {
            Self::Error
        }
    }
}

/// Check if a given session description contains at least one H.264 or
/// a general MPEG4 video stream.
fn is_supported_rtsp_service(sdp: &[u8]) -> bool {
    if let Ok(sdp) = SessionDescription::parse(sdp) {
        let mut vcodecs = HashSet::new();

        let video_streams = sdp
            .media_descriptions
            .into_iter()
            .filter(|md| md.media_type == MediaType::Video);

        for md in video_streams {
            for attr in md.attributes {
                if let Ok(rtpmap) = RTPMap::from_attr(&attr) {
                    vcodecs.insert(rtpmap.encoding.to_uppercase());
                }
            }
        }

        vcodecs.contains("H264")
            || vcodecs.contains("H264-RCDO")
            || vcodecs.contains("H264-SVC")
            || vcodecs.contains("MP4V-ES")
            || vcodecs.contains("MPEG4-GENERIC")
    } else {
        false
    }
}

/// Check if a given HTTP response can be interpreted as an MJPEG stream.
fn is_supported_mjpeg_service(response: &HttpResponse) -> bool {
    let ctype = response
        .get_header_field_value("content-type")
        .unwrap_or("")
        .to_lowercase();

    ctype.starts_with("multipart/x-mixed-replace")
        || ctype.starts_with("image/jpeg")
        || ctype.starts_with("image/jpg")
}

/// Check if a given service is an RTSP service.
async fn is_rtsp_service(context: Context, addr: SocketAddr) -> bool {
    let request = RtspRequest::options(&format!("rtsp://{}/", addr));

    if request.is_err() {
        return false;
    }

    request
        .unwrap()
        .set_request_timeout(Some(context.get_request_timeout()))
        .send()
        .await
        .is_ok()
}

/// Check if a given service is an HTTP service.
async fn is_http_service(context: Context, addr: SocketAddr) -> bool {
    get_http_response(context, addr, "/").await.is_ok()
}

/// Get HTTP response for a given path from a given HTTP server.
async fn get_http_response(context: Context, addr: SocketAddr, path: &str) -> Result<HttpResponse> {
    HttpRequest::get_header(&format!("http://{}{}", addr, path))
        .map_err(|err| Error::from_static_msg_and_cause("HTTP client error", err))?
        .set_request_timeout(Some(context.get_request_timeout()))
        .send()
        .await
        .map_err(|err| Error::from_static_msg_and_cause("HTTP client error", err))
}

/// Find all RTSP services.
async fn find_rtsp_services<I>(context: Context, open_ports: I) -> Vec<(MacAddr, SocketAddr)>
where
    I: IntoIterator<Item = (MacAddr, SocketAddr)>,
{
    debug!("looking for RTSP services");

    let filtered = filter_services(context, open_ports, |context, saddr| async move {
        if context.is_rtsp_port_candidate(saddr.port()) {
            is_rtsp_service(context, saddr).await
        } else {
            false
        }
    });

    filtered.await
}

/// Find all HTTP services.
async fn find_http_services<I>(context: Context, open_ports: I) -> Vec<(MacAddr, SocketAddr)>
where
    I: IntoIterator<Item = (MacAddr, SocketAddr)>,
{
    debug!("looking for HTTP services");

    let filtered = filter_services(context, open_ports, |context, saddr| async move {
        if context.is_http_port_candidate(saddr.port()) {
            is_http_service(context, saddr).await
        } else {
            false
        }
    });

    filtered.await
}

/// Filter a given list of services using a given async predicate.
async fn filter_services<I, P, F>(
    context: Context,
    candidates: I,
    predicate: P,
) -> Vec<(MacAddr, SocketAddr)>
where
    I: IntoIterator<Item = (MacAddr, SocketAddr)>,
    P: Fn(Context, SocketAddr) -> F,
    F: Future<Output = bool>,
{
    let futures = candidates
        .into_iter()
        .map(|(mac, saddr)| predicate(context.clone(), saddr).map(move |res| (mac, saddr, res)));

    futures::future::join_all(futures)
        .await
        .into_iter()
        .filter_map(
            |(mac, saddr, res)| {
                if res { Some((mac, saddr)) } else { None }
            },
        )
        .collect()
}

/// Filter out duplicit services from a given list using given priorities.
fn filter_duplicit_services<I>(
    services: I,
    port_priorities: &HashMap<u16, usize>,
) -> Vec<(MacAddr, SocketAddr)>
where
    I: IntoIterator<Item = (MacAddr, SocketAddr)>,
{
    let mut svc_map = HashMap::new();

    for (mac, saddr) in services {
        let ip = saddr.ip();
        let port = saddr.port();

        svc_map
            .entry(ip)
            .and_modify(|v| {
                let &mut (_, _, old_port) = v;

                let old_priority = port_priorities.get(&old_port).cloned().unwrap_or(0);
                let new_priority = port_priorities.get(&port).cloned().unwrap_or(0);

                if new_priority > old_priority {
                    *v = (mac, ip, port);
                }
            })
            .or_insert((mac, ip, port));
    }

    svc_map
        .into_iter()
        .map(|(_, (mac, ip, port))| match ip {
            IpAddr::V4(ip) => (mac, SocketAddr::V4(SocketAddrV4::new(ip, port))),
            IpAddr::V6(ip) => (mac, SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))),
        })
        .collect::<_>()
}

/// Find all RTSP streams.
async fn find_rtsp_streams<I>(context: Context, rtsp_services: I) -> Vec<Service>
where
    I: IntoIterator<Item = (MacAddr, SocketAddr)>,
{
    debug!("looking for RTSP streams");

    let futures = rtsp_services
        .into_iter()
        .map(|(mac, addr)| find_rtsp_stream(context.clone(), mac, addr));

    futures::future::join_all(futures).await
}

/// Find the first available RTSP stream for a given RTSP service.
async fn find_rtsp_stream(context: Context, mac: MacAddr, addr: SocketAddr) -> Service {
    let paths = context.get_rtsp_paths();

    let mut res = Service::unknown_rtsp(mac, addr);

    for path in paths.iter() {
        let service = get_rtsp_stream(context.clone(), mac, addr, path);

        if let Some(svc) = service.await {
            if svc.service_type() == ServiceType::RTSP
                || svc.service_type() == ServiceType::LockedRTSP
            {
                return svc;
            } else {
                res = svc;
            }
        }
    }

    res
}

/// Get RTSP stream or None for a given RTSP service and path.
async fn get_rtsp_stream(
    context: Context,
    mac: MacAddr,
    addr: SocketAddr,
    path: &str,
) -> Option<Service> {
    let path = path.to_string();

    let stream_type = get_rtsp_stream_type(context, addr, &path);

    match stream_type.await {
        StreamType::Supported => Some(Service::rtsp(mac, addr, path)),
        StreamType::Unsupported => Some(Service::unsupported_rtsp(mac, addr, path)),
        StreamType::Locked => Some(Service::locked_rtsp(mac, addr, None)),

        _ => None,
    }
}

/// Get stream type for a given RTSP service and path.
async fn get_rtsp_stream_type(context: Context, addr: SocketAddr, path: &str) -> StreamType {
    let path = path.to_string();

    let request = RtspRequest::describe(&format!("rtsp://{}{}", addr, path));

    if request.is_err() {
        return StreamType::Error;
    }

    request
        .unwrap()
        .set_request_timeout(Some(context.get_request_timeout()))
        .send()
        .await
        .map(|response| {
            if is_hipcam_rtsp_response(&response) && path != "/11" && path != "/12" {
                StreamType::NotFound
            } else {
                StreamType::from(response)
            }
        })
        .unwrap_or(StreamType::Error)
}

/// Check if a given RTSP response is from a buggy Hi(I)pcam RTSP server.
fn is_hipcam_rtsp_response(response: &RtspResponse) -> bool {
    matches!(
        response.get_header_field_value("server"),
        Some("HiIpcam/V100R003 VodServer/1.0.0") | Some("Hipcam RealServer/V1.0"),
    )
}

/// Find all MJPEG streams.
async fn find_mjpeg_streams<I>(context: Context, mjpeg_services: I) -> Vec<Service>
where
    I: IntoIterator<Item = (MacAddr, SocketAddr)>,
{
    debug!("looking for MJPEG streams");

    let futures = mjpeg_services
        .into_iter()
        .map(|(mac, addr)| find_mjpeg_path(context.clone(), mac, addr));

    futures::future::join_all(futures)
        .await
        .into_iter()
        .flatten()
        .collect()
}

/// Find the first available MJPEG stream for a given HTTP service.
async fn find_mjpeg_path(context: Context, mac: MacAddr, addr: SocketAddr) -> Option<Service> {
    let paths = context.get_mjpeg_paths();

    for path in paths.iter() {
        let service = get_mjpeg_stream(context.clone(), mac, addr, path);

        if let Some(svc) = service.await {
            return Some(svc);
        }
    }

    None
}

/// Get MJPEG stream or None for a given HTTP service and path.
async fn get_mjpeg_stream(
    context: Context,
    mac: MacAddr,
    addr: SocketAddr,
    path: &str,
) -> Option<Service> {
    let path = path.to_string();

    get_http_response(context, addr, &path)
        .await
        .map(|response| match StreamType::from(response) {
            StreamType::Supported => Some(Service::mjpeg(mac, addr, path)),
            StreamType::Locked => Some(Service::locked_mjpeg(mac, addr, None)),

            _ => None,
        })
        .unwrap_or(None)
}

#[cfg(test)]
use std::net::Ipv4Addr;

#[cfg(test)]
#[test]
/// Test the service priority filtering function.
fn test_service_filtering() {
    let ports = [554, 80];
    let mac = MacAddr::new(0, 0, 0, 0, 0, 0);
    let ip = Ipv4Addr::new(0, 0, 0, 0);

    let mut services = Vec::new();

    services.push((mac, SocketAddr::V4(SocketAddrV4::new(ip, 80))));
    services.push((mac, SocketAddr::V4(SocketAddrV4::new(ip, 554))));

    let port_priorities = get_port_priorities(&ports);

    let services = filter_duplicit_services(services, &port_priorities);

    assert_eq!(services.len(), 1);
    assert_eq!(services[0].1.port(), 554);
}
