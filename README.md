# Arrow Client

[![Build Status](https://travis-ci.org/angelcam/arrow-client.svg?branch=master)](https://travis-ci.org/angelcam/arrow-client)

Arrow Client is an application used to simplify the process of connecting IP 
cameras to the Angelcam cloud services. The Arrow Client is meant to be shipped 
together with IP camera firmwares or as a standalone application for various 
devices such as Raspberry Pi. It can connect to RTSP services passed as 
command line arguments and optionally, it can be also compiled with a network 
scanning feature. This feature allows the client to scan all its network 
interfaces and find local RTSP services automatically. All such RTSP services 
can be registered within Angelcam cloud services under your Angelcam account 
without the need of a public IP address and setting up your firewall.

This is a reference implementation of the Arrow Client role described in 
[Arrow Protocol](https://github.com/angelcam/arrow-client/wiki/Arrow-Protocol "Arrow Protocol").

## Features

- Automatic RTSP service discovery
- Zero-conf IP camera connection
- Connection to Angelcam cloud services secured using TLS v1.2
- Secure pairing with your Angelcam account

## Usage

The application requires `/etc/arrow` directory for storing its configuration 
file generated on the first start. The directory must also contain a file named 
`rtsp-paths` in case the network scanning feature is enabled. The file should 
contain RTSP paths that will be checked on an RTSP service discovery. You can 
use the `rtsp-paths` file from this repository. In order to start the 
application, you have to pass address of the Angelcam Arrow Service and 
certificate file for the service verification. Address of the Angelcam Arrow 
Service is:

```
arr-rs.angelcam.com:8900
```

Currently, a self-signed certificate is used. You can find the certificate in 
this repository (file `ca.pem`). The certificate will be later replaced by 
a proper CA certificate.

Here is an example of starting the Arrow Client with one fixed RTSP service and 
with network scanning enabled:

```bash
arrow-client arr-rs.angelcam.com:8900 -c ca.pem -d -r "rtsp://localhost:8554/stream.sdp?prof=baseline&res=low"
```

Note that the application requires root privileges for direct access to local 
network interfaces.

## Dependencies

This application requires the following native libraries:

- OpenSSL
- libpcap (this dependency is optional, it is required only when the network 
    scanning feature is enabled)

and the following Rust libraries (downloaded automatically on build):

- libc
- regex
- mio
- uuid
- time
- rustc-serialize
- openssl

## Compilation

Arrow Client compilation is currently supported for x86, x86\_64 and ARM 
platforms. Compilation for x86 and x86\_64 can be done directly on 
a particular machine. ARM binaries can be compiled using a cross-compiler or 
directly in the target or in a virtualized environment (e.g. QEMU).

### Direct compilation on x86, x86\_64 or ARM

- Download and install Rust build environment (in case you do not already 
  have one) from https://www.rust-lang.org/install.html. 
- Use the following commands to build the Arrow Client binary:
   
```bash
# to build Arrow Client:
cargo build --release
# to build Arrow Client with network scanning feature:
cargo build --release --features "discovery"
```

- You will find the binary in the `target/release/` subdir.
- Run the application without any arguments to see its usage.

### Cross-compilation

First of all, you will need gcc cross-compiler. In case of ARM, you can 
download it from https://github.com/raspberrypi/tools. You will also have to 
add some essential libraries for the target architecture (e.g. OpenSSL).

Now, you need to get your copy of Rust:

```bash
git clone https://github.com/rust-lang/rust.git
```

Add the gcc cross-compiler into the PATH env. variable, e.g.:

```bash
export PATH=~/pi-tools/arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian-x64/bin:$PATH
```

Then build the Rust cross-compiler, e.g.:

```bash
./configure --target=arm-unknown-linux-gnueabihf && make && make install
```

When the Rust cross-compiler is ready, you will have to modify your 
cargo configuration in order to tell the Rust compiler the name of your gcc 
linker for the target architecture. For `arm-unknown-linux-gnueabihf` target, 
insert the following configuration into your `~/.cargo/config`:

```toml
[target.arm-unknown-linux-gnueabihf]
ar     = "arm-linux-gnueabihf-ar"
linker = "arm-linux-gnueabihf-gcc"
```

Finally, set CC env. variable to the path of your gcc cross-compiler, e.g.:

```bash
export CC=~/pi-tools/arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian-x64/bin/arm-linux-gnueabihf-gcc
```

and add libraries for the target architecture into the LD_LIBRARY_PATH env. 
variable, e.g.:

```bash
export LD_LIBRARY_PATH=~/pi-tools/arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian-x64/lib:$LD_LIBRARY_PATH
```

Now, you are ready to build the Arrow Client for the target architecture, e.g.:

```bash
# to build Arrow Client:
cargo build --target=arm-unknown-linux-gnueabihf --release
# to build Arrow Client with network scanning feature:
cargo build --target=arm-unknown-linux-gnueabihf --release --features "discovery"
```
