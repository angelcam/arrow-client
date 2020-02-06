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

use std::env;

use cc::Build;

fn main() {
    let platform = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        panic!("Unsupported OS")
    };

    Build::new()
        .include("src/net/raw/devices")
        .file("src/net/raw/devices/devices-common.c")
        .file(&format!("src/net/raw/devices/devices-{}.c", platform))
        .compile("net_devices");

    if cfg!(feature = "discovery") {
        let mut wrapper_builder = Build::new();

        if cfg!(target_os = "windows") {
            let lib = vcpkg::Config::new()
                .cargo_metadata(true)
                .emit_includes(false)
                .copy_dlls(false)
                .find_package("winpcap")
                .unwrap();

            for include in lib.include_paths {
                wrapper_builder.include(include);
            }
        } else {
            link("pcap");
        }

        wrapper_builder
            .include("src/net/raw/pcap")
            .file("src/net/raw/pcap/wrapper-common.c")
            .file(&format!("src/net/raw/pcap/wrapper-{}.c", platform))
            .compile("pcap_wrapper");
    }
}

fn link(lib: &str) {
    println!("cargo:rustc-link-lib={}={}", lib_mode(lib), lib);
}

fn lib_mode(lib: &str) -> &'static str {
    let kind = env::var(&format!("LIB{}_STATIC", lib.to_uppercase()));

    match kind.ok().as_ref().map(|v| v.as_str()) {
        Some("0") => "dylib",
        Some(_) => "static",
        None => "dylib",
    }
}
