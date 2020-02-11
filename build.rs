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

use std::path::Path;

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
        .include("src")
        .include("src/net/raw/devices")
        .file("src/net/raw/devices/devices-common.c")
        .file(&format!("src/net/raw/devices/devices-{}.c", platform))
        .compile("net_devices");

    if cfg!(feature = "discovery") {
        let mut wrapper_builder = Build::new();

        if cfg!(target_os = "windows") {
            // on Windows, we primarily try to find the lib using vcpkg
            let lib = vcpkg::Config::new()
                .cargo_metadata(true)
                .emit_includes(false)
                .copy_dlls(false)
                .find_package("winpcap");

            if let Ok(lib) = lib {
                for include in lib.include_paths {
                    wrapper_builder.include(include);
                }
            } else {
                // if vcpkg cannot find the lib, we try the env. variables
                if let Some(dir) = dir_from_var("WINPCAP_LIB_DIR") {
                    emit_lib_path(&dir);
                }

                if let Some(dir) = dir_from_var("WINPCAP_INCLUDE_DIR") {
                    wrapper_builder.include(dir);
                }

                link("winpcap", "WINPCAP_STATIC");
            }
        } else {
            // on other platforms, we expect the lib will be in standard paths or the paths will be
            // defined using env. variables
            if let Some(dir) = dir_from_var("LIBPCAP_LIB_DIR") {
                emit_lib_path(&dir);
            }

            if let Some(dir) = dir_from_var("LIBPCAP_INCLUDE_DIR") {
                wrapper_builder.include(dir);
            }

            link("pcap", "LIBPCAP_STATIC");
        }

        wrapper_builder
            .include("src")
            .include("src/net/raw/pcap")
            .file("src/net/raw/pcap/wrapper-common.c")
            .file(&format!("src/net/raw/pcap/wrapper-{}.c", platform))
            .compile("pcap_wrapper");
    }
}

fn is_dir(d: &str) -> bool {
    let path = Path::new(d);

    path.is_dir()
}

fn link(lib: &str, static_flag_var: &str) {
    println!("cargo:rustc-link-lib={}={}", lib_mode(static_flag_var), lib);
}

fn emit_lib_path(path: &str) {
    println!("cargo:rustc-link-search=native={}", path);
}

fn lib_mode(static_flag_var: &str) -> &'static str {
    let kind = env::var(static_flag_var);

    match kind.ok().as_ref().map(|v| v.as_str()) {
        Some("0") => "dylib",
        Some(_) => "static",
        None => "dylib",
    }
}

fn dir_from_var(var: &str) -> Option<String> {
    if let Ok(dir) = env::var(var) {
        if is_dir(&dir) {
            return Some(dir);
        }
    }

    None
}
