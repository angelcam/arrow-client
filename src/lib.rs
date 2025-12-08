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

//! Arrow Client definitions.

#[macro_use]
extern crate log;

#[doc(hidden)]
pub mod tls;

#[doc(hidden)]
#[macro_use]
pub mod utils;

#[doc(hidden)]
pub mod client;

#[doc(hidden)]
pub mod cmd_handler;

pub mod config;

#[doc(hidden)]
pub mod context;

#[doc(hidden)]
pub mod error;

#[doc(hidden)]
pub mod net;

#[doc(hidden)]
pub mod scanner;

pub mod storage;

#[doc(hidden)]
pub mod svc_table;

pub use crate::{
    client::{
        ArrowClient, ArrowClientTask, DefaultServiceConnector, ServiceConnection, ServiceConnector,
    },
    config::ClientId,
    context::{ApplicationEventListener as ArrowClientEventListener, ConnectionState},
};

pub mod logger {
    pub use crate::utils::logger::{FileLogger, StderrLogger};

    #[cfg(not(target_os = "windows"))]
    pub use crate::utils::logger::Syslog;
}
