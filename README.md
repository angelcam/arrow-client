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

- OpenSSL 1.0.x or 1.1.x
- libpcap 1.6.x or later (optional)

## Compilation

See the following guides for more info:

* [Quick Start](https://github.com/angelcam/arrow-client/wiki/Quick-Start)
* [Compilation](https://github.com/angelcam/arrow-client/wiki/Compilation)
* [Compilation for OpenWrt and LEDE](https://github.com/angelcam/arrow-client/wiki/Compilation-for-OpenWrt-and-LEDE)
* [Optimizations](https://github.com/angelcam/arrow-client/wiki/Optimizations)
* [Integration best practices](https://github.com/angelcam/arrow-client/wiki/Integration-best-practices)
