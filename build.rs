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

extern crate cc;

use std::env;

use cc::Build;

fn main() {
    Build::new()
        .file("src/net/raw/devices.c")
        .compile("net_devices");

    if cfg!(feature = "discovery") {
        link("pcap");
    }
}

fn link(lib: &str) {
    println!("cargo:rustc-link-lib={}={}", lib_mode(lib), lib);
}

fn lib_mode(lib: &str) -> &'static str {
    let kind = env::var(&format!("LIB{}_STATIC", lib.to_uppercase()));

    match kind.ok().as_ref().map(|v| v.as_str()) {
        Some("0") => "dylib",
        Some(_)   => "static",
        None      => "dylib",
   }
}
