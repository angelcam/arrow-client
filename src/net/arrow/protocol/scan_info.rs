// Copyright 2016 click2stream, Inc.
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

//! Scan info message definitions.

use std::io;

use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::collections::{HashSet, HashMap};
use std::collections::hash_set::Iter as HashSetIterator;
use std::collections::hash_map::Iter as HashMapIterator;

use utils::Serialize;
use net::raw::ether::MacAddr;
use net::arrow::protocol::{Service, ServiceTable};

pub use self::host_info::HINFO_FLAG_ARP;
pub use self::host_info::HINFO_FLAG_ICMP;

pub use self::host_info::HostInfo;

type HostInfoKey = (MacAddr, IpAddr);

/// Network scan info.
#[derive(Debug, Clone)]
pub struct NetworkScanInfo {
    hosts:    HashMap<HostInfoKey, HostInfo>,
    services: HashSet<Service>
}

impl NetworkScanInfo {
    /// Create a new network scan info record.
    pub fn new() -> NetworkScanInfo {
        NetworkScanInfo {
            hosts:    HashMap::new(),
            services: HashSet::new()
        }
    }
    
    /// Add a given host.
    pub fn add_host(&mut self, mac: MacAddr, ip: IpAddr, flags: u8) {
        let key = (mac, ip);
        if !self.hosts.contains_key(&key) {
            self.hosts.insert(key, HostInfo::new(mac, ip, flags));
        } else if let Some(host) = self.hosts.get_mut(&key) {
            host.flags |= flags;
        }
    }
    
    /// Get host info for a given host.
    pub fn get_host(&self, mac: MacAddr, ip: IpAddr) -> Option<&HostInfo> {
        self.hosts.get(&(mac, ip))
    }
    
    /// Get mutable host info for a given host.
    pub fn get_host_mut(
        &mut self, 
        mac: MacAddr, 
        ip: IpAddr) -> Option<&mut HostInfo> {
        self.hosts.get_mut(&(mac, ip))
    }
    
    /// Add a given port into the corresponding host info. The host info is 
    /// created if it is not already in the table.
    pub fn add_port(&mut self, mac: MacAddr, ip: IpAddr, port: u16) {
        let key = (mac, ip);
        
        if !self.hosts.contains_key(&key) {
            self.hosts.insert(key, HostInfo::new(mac, ip, 0));
        }
        
        if let Some(host) = self.hosts.get_mut(&key) {
            host.add_port(port);
        }
    }
    
    /// Add a given service.
    pub fn add_service(&mut self, svc: Service) {
        self.services.insert(svc);
    }
    
    /// Get host infos.
    pub fn hosts(&self) -> HostInfoIterator {
        HostInfoIterator::new(self.hosts.iter())
    }
    
    pub fn socket_addrs(&self) -> SocketAddrIterator {
        SocketAddrIterator::new(self.hosts())
    }
    
    /// Get services.
    pub fn services(&self) -> ServiceIterator {
        ServiceIterator::new(self.services.iter())
    }
    
    /// Merge with a given scan info.
    pub fn merge(&mut self, other: NetworkScanInfo) {
        for (key, other_host) in other.hosts {
            if !self.hosts.contains_key(&key) {
                self.hosts.insert(key, other_host);
            } else if let Some(host) = self.hosts.get_mut(&key) {
                host.add_ports(other_host.ports());
                host.flags |= other_host.flags;
            }
        }
        
        self.services.extend(other.services);
    }
    
    /// Serialize the scan info.
    ///
    /// Note: A service table is required in order to get service IDs for all
    /// serialized services.
    pub fn serialize<W: Write>(
        &self, 
        w: &mut W, 
        svc_table: &ServiceTable) -> io::Result<()> {
        let host_count = self.hosts.len() as u32;
        try!(host_count.serialize(w));
        for (_, ref host) in &self.hosts {
            try!(host.serialize(w));
        }
        
        for svc in &self.services {
            let id = svc_table.get_id(svc)
                .unwrap_or(0xffff);
            
            try!(svc.serialize(w, id));
        }
        
        let cp_svc = Service::ControlProtocol;
        
        cp_svc.serialize(w, 0)
    }
}

/// Host info iterator.
#[derive(Clone)]
pub struct HostInfoIterator<'a> {
    inner: HashMapIterator<'a, HostInfoKey, HostInfo>,
}

impl<'a> HostInfoIterator<'a> {
    /// Create a new host info iterator from a given hash map iterator.
    fn new(inner: HashMapIterator<'a, HostInfoKey, HostInfo>) -> HostInfoIterator<'a> {
        HostInfoIterator {
            inner: inner
        }
    }
}

impl<'a> Iterator for HostInfoIterator<'a> {
    type Item = &'a HostInfo;
    
    fn next(&mut self) -> Option<&'a HostInfo> {
        self.inner.next()
            .map(|(_, host)| host)
    }
}

impl<'a> ExactSizeIterator for HostInfoIterator<'a> {
    fn len(&self) -> usize {
        self.inner.len()
    }
}

/// Service iterator.
#[derive(Clone)]
pub struct ServiceIterator<'a> {
    inner: HashSetIterator<'a, Service>,
}

impl<'a> ServiceIterator<'a> {
    /// Create a new service iterator from a given hash set iterator.
    fn new(inner: HashSetIterator<'a, Service>) -> ServiceIterator<'a> {
        ServiceIterator {
            inner: inner
        }
    }
}

impl<'a> Iterator for ServiceIterator<'a> {
    type Item = &'a Service;
    
    fn next(&mut self) -> Option<&'a Service> {
        self.inner.next()
    }
}

impl<'a> ExactSizeIterator for ServiceIterator<'a> {
    fn len(&self) -> usize {
        self.inner.len()
    }
}

/// Socket address iterator.
#[derive(Clone)]
pub struct SocketAddrIterator<'a> {
    host_iterator:  HostInfoIterator<'a>,
    saddr_iterator: Option<host_info::SocketAddrIterator<'a>>,
}

impl<'a> SocketAddrIterator<'a> {
    /// Create a new socket address iterator from a given host info iterator.
    fn new(mut host_iterator: HostInfoIterator<'a>) -> SocketAddrIterator<'a> {
        let saddr_iterator = host_iterator.next()
            .map(|host| host.socket_addrs());
        
        SocketAddrIterator {
            host_iterator:  host_iterator,
            saddr_iterator: saddr_iterator
        }
    }
}

impl<'a> Iterator for SocketAddrIterator<'a> {
    type Item = (MacAddr, SocketAddr);
    
    fn next(&mut self) -> Option<(MacAddr, SocketAddr)> {
        while self.saddr_iterator.is_some() {
            let saddr = self.saddr_iterator.as_mut()
                .and_then(|saddr_iterator| saddr_iterator.next());
            
            if saddr.is_some() {
                return saddr;
            }
            
            self.saddr_iterator = self.host_iterator.next()
                .map(|host| host.socket_addrs());
        }
        
        None
    }
}

/// Host info submodule.
mod host_info {
    
    use std::io;
    
    use std::io::Write;
    use std::collections::HashSet;
    use std::collections::hash_set::Iter as HashSetIterator;
    use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
    
    use utils;
    
    use utils::Serialize;
    use net::utils::IpAddrEx;
    use net::raw::ether::MacAddr;
    
    pub const HINFO_FLAG_ARP: u8  = 0x01;
    pub const HINFO_FLAG_ICMP: u8 = 0x02;

    /// Host info.
    #[derive(Debug, Clone)]
    pub struct HostInfo {
        pub flags:    u8,
        pub mac_addr: MacAddr,
        pub ip_addr:  IpAddr,
        ports:        HashSet<u16>,
    }

    impl HostInfo {
        /// Create a new instance of host info.
        pub fn new(mac: MacAddr, ip: IpAddr, flags: u8) -> HostInfo {
            HostInfo {
                flags:    flags,
                mac_addr: mac,
                ip_addr:  ip,
                ports:    HashSet::new()
            }
        }
        
        /// Add a given port.
        pub fn add_port(&mut self, port: u16) {
            self.ports.insert(port);
        }
        
        /// Add ports from a given iterator.
        pub fn add_ports<I>(&mut self, ports: I) where I: IntoIterator<Item=u16> {
            self.ports.extend(ports);
        }
        
        /// Get port iterator.
        pub fn ports(&self) -> PortIterator {
            PortIterator::new(self.ports.iter())
        }
        
        /// Get socket address iterator.
        pub fn socket_addrs(&self) -> SocketAddrIterator {
            SocketAddrIterator::new(self)
        }
    }

    impl Serialize for HostInfo {
        fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
            let header = HostInfoHeader::new(self);
            
            try!(header.serialize(w));
            for port in &self.ports {
                try!(port.serialize(w));
            }
            
            Ok(())
        }
    }

    /// Raw host info.
    #[repr(packed)]
    #[derive(Copy, Clone)]
    struct HostInfoHeader {
        flags:       u8,
        mac_address: [u8; 6],
        ip_version:  u8,
        ip_address:  [u8; 16],
        port_count:  u16,
    }

    impl HostInfoHeader {
        fn new(host: &HostInfo) -> HostInfoHeader {
            HostInfoHeader {
                flags:       host.flags,
                mac_address: host.mac_addr.octets(),
                ip_version:  host.ip_addr.version(),
                ip_address:  host.ip_addr.bytes(),
                port_count:  host.ports.len() as u16
            }
        }
    }

    impl Serialize for HostInfoHeader {
        fn serialize<W: Write>(&self, w: &mut W) -> io::Result<()> {
            let be_header = HostInfoHeader {
                flags:       self.flags,
                mac_address: self.mac_address,
                ip_version:  self.ip_version,
                ip_address:  self.ip_address,
                port_count:  self.port_count.to_be()
            };
            
            w.write_all(utils::as_bytes(&be_header))
        }
    }
    
    /// Port iterator.
    #[derive(Clone)]
    pub struct PortIterator<'a> {
        inner: HashSetIterator<'a, u16>,
    }

    impl<'a> PortIterator<'a> {
        /// Create a new port iterator from a given hash set iterator.
        fn new(inner: HashSetIterator<'a, u16>) -> PortIterator<'a> {
            PortIterator {
                inner: inner
            }
        }
    }

    impl<'a> Iterator for PortIterator<'a> {
        type Item = u16;
        
        fn next(&mut self) -> Option<u16> {
            self.inner.next()
                .map(|port| *port)
        }
    }

    impl<'a> ExactSizeIterator for PortIterator<'a> {
        fn len(&self) -> usize {
            self.inner.len()
        }
    }
    
    /// Socket address iterator.
    #[derive(Clone)]
    pub struct SocketAddrIterator<'a> {
        port_iterator: PortIterator<'a>,
        mac_addr:      MacAddr,
        ip_addr:       IpAddr,
    }

    impl<'a> SocketAddrIterator<'a> {
        /// Create a new socket address iterator for a given host info.
        fn new(host: &'a HostInfo) -> SocketAddrIterator<'a> {
            SocketAddrIterator {
                port_iterator: host.ports(),
                mac_addr:      host.mac_addr,
                ip_addr:       host.ip_addr
            }
        }
    }

    impl<'a> Iterator for SocketAddrIterator<'a> {
        type Item = (MacAddr, SocketAddr);
        
        fn next(&mut self) -> Option<(MacAddr, SocketAddr)> {
            if let Some(port) = self.port_iterator.next() {
                let res = match self.ip_addr {
                    IpAddr::V4(ip_addr) => SocketAddr::V4(SocketAddrV4::new(ip_addr, port)),
                    IpAddr::V6(ip_addr) => SocketAddr::V6(SocketAddrV6::new(ip_addr, port, 0, 0))
                };
                
                Some((self.mac_addr, res))
            } else {
                None
            }
        }
    }

    impl<'a> ExactSizeIterator for SocketAddrIterator<'a> {
        fn len(&self) -> usize {
            self.port_iterator.len()
        }
    }
}
