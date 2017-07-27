# Arrow Client

[![Build Status](https://travis-ci.org/angelcam/arrow-client.svg?branch=master)](https://travis-ci.org/angelcam/arrow-client)

Arrow Client is an application used to simplify the process of connecting IP 
cameras to the Angelcam cloud. The Arrow Client is intended to be shipped 
together with IP camera firmwares or as a standalone application for various 
devices such as Raspberry Pi. It can connect to RTSP and MJPEG services passed
as command line arguments and, optionally, it can be also compiled with a
network scanning feature. This feature allows the client to scan all its
network interfaces and find local RTSP and MJPEG services automatically. All
such services can be registered within Angelcam cloud under your Angelcam
account without the need of a public IP address and setting up your firewall.

This is a reference implementation of the Arrow Client role described in 
[Arrow Protocol](https://github.com/angelcam/arrow-client/wiki/Arrow-Protocol "Arrow Protocol").
If you are interested in integration or you just want to play with the client 
a little, please see our 
[Quick Start guide](https://github.com/angelcam/arrow-client/wiki/Quick-Start "Quick Start guide").

## Features

- Automatic RTSP and MJPEG service discovery
- Zero-conf IP camera connection
- Remote access to HTTP-based IP camera admin interfaces
- Connection to Angelcam cloud services secured using TLS v1.2
- Secure pairing with your Angelcam account

## Usage

The application requires `/etc/arrow` directory for storing its configuration 
file generated on the first start (the path to the configuration file can be
changed using a command line argument). The directory must also contain files
named `rtsp-paths` and `mjpeg-paths` in case the network scanning feature is
enabled. The files should contain RTSP paths and MJPEG paths that will be
checked on service discovery. You can use the files from this repository. In
order to start the application, you have to pass address of the Angelcam Arrow
Service and certificate file for the service verification. Address of the
Angelcam Arrow Service is:

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
network interfaces. Alternatively, you can use the NET\_CAP\_RAW capability.

## Dependencies

This application requires the following native libraries:

- OpenSSL
- libpcap (this dependency is optional, it is required only when the network 
    scanning feature is enabled)

## Compilation

Arrow Client compilation is currently supported for x86, x86\_64 and ARM 
platforms based on GNU libc. Compilation for x86 and x86\_64 can be done
directly on a particular machine. ARM binaries can be compiled using a
cross-compiler or directly in the target or in a virtualized environment
(e.g. QEMU).

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

First of all, you will need a linker for the target architecture. In case of
`arm-unknown-linux-gnueabihf`, you can download it from
https://github.com/raspberrypi/tools. You will also have to add some essential
libraries for the target architecture (e.g. OpenSSL). You can get these
libraries from the repositories of your favourite distribution or you can
build them on your own.

Add the linker into the PATH env. variable, e.g.:

```bash
export PATH=~/pi-tools/arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian-x64/bin:$PATH
```

Download and install Rust standard library for the target architecture, e.g.:

```bash
rustup target add arm-unknown-linux-gnueabihf
```

Modify your cargo configuration in order to tell the Rust compiler the name of
your linker for the target architecture. For `arm-unknown-linux-gnueabihf`
target and pi-tools, insert the following configuration into your
`~/.cargo/config`:

```toml
[target.arm-unknown-linux-gnueabihf]
ar     = "arm-linux-gnueabihf-ar"
linker = "arm-linux-gnueabihf-gcc"
```

Now, you are ready to build the Arrow Client for the target architecture, e.g.:

```bash
# to build Arrow Client:
cargo build --target=arm-unknown-linux-gnueabihf --release
# to build Arrow Client with network scanning feature:
cargo build --target=arm-unknown-linux-gnueabihf --release --features "discovery"
```
