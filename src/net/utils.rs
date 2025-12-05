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

use std::{
    io,
    net::{SocketAddr, ToSocketAddrs},
};

/// Get socket address from a given argument.
pub fn get_socket_address<T>(s: T) -> io::Result<SocketAddr>
where
    T: ToSocketAddrs,
{
    s.to_socket_addrs()
        .map_err(|_| io::Error::other("unable to get socket address"))?
        .next()
        .ok_or_else(|| io::Error::other("unable to get socket address"))
}
