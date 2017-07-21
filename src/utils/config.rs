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

//! Arrow Box config definitions.

/*use std::io;
use std::fmt;
use std::net;
use std::result;

use std::fs::File;
use std::borrow::Cow;
use std::error::Error;
use std::io::{BufReader, BufWriter, Read, Write};
use std::fmt::{Display, Formatter};

use net::raw::ether;

use net::arrow::protocol::ScanReport;

use net::arrow::protocol::{Service, ServiceTable};

use uuid;

use uuid::Uuid;

use rustc_serialize::json;

/// Arrow configuration loading/parsing/saving error.
#[derive(Debug, Clone)]
pub struct ConfigError {
    msg: String,
}

impl Error for ConfigError {
    fn description(&self) -> &str {
        &self.msg
    }
}

impl Display for ConfigError {
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        f.write_str(self.description())
    }
}

impl From<String> for ConfigError {
    fn from(msg: String) -> ConfigError {
        ConfigError { msg: msg }
    }
}

impl<'a> From<&'a str> for ConfigError {
    fn from(msg: &'a str) -> ConfigError {
        ConfigError::from(msg.to_string())
    }
}

impl From<io::Error> for ConfigError {
    fn from(err: io::Error) -> ConfigError {
        ConfigError::from(format!("{}", err))
    }
}

impl From<json::DecoderError> for ConfigError {
    fn from(err: json::DecoderError) -> ConfigError {
        ConfigError::from(format!("{}", err))
    }
}

impl From<json::EncoderError> for ConfigError {
    fn from(err: json::EncoderError) -> ConfigError {
        ConfigError::from(format!("{}", err))
    }
}

impl From<uuid::ParseError> for ConfigError {
    fn from(err: uuid::ParseError) -> ConfigError {
        ConfigError::from(format!("{}", err))
    }
}

impl From<ether::AddrParseError> for ConfigError {
    fn from(err: ether::AddrParseError) -> ConfigError {
        ConfigError::from(format!("{}", err))
    }
}

impl From<net::AddrParseError> for ConfigError {
    fn from(err: net::AddrParseError) -> ConfigError {
        ConfigError::from(format!("{}", err))
    }
}

/// Type alias for Arrow configuration results.
pub type Result<T> = result::Result<T, ConfigError>;

/// JSON mapping for the Arrow client configuration.
#[derive(Debug, Clone, RustcDecodable, RustcEncodable)]
struct JsonConfig<'a> {
    uuid:      String,
    passwd:    String,
    version:   usize,
    svc_table: Cow<'a, ServiceTable>,
}

impl<'a> JsonConfig<'a> {
    /// Create a new JsonConfig instance.
    fn new(
        uuid: String,
        passwd: String,
        version: usize,
        svc_table: &'a ServiceTable) -> JsonConfig<'a> {
        JsonConfig {
            uuid:      uuid,
            passwd:    passwd,
            version:   version,
            svc_table: Cow::Borrowed(svc_table)
        }
    }

    /// Load configuration from a given file.
    fn load(file: &str) -> Result<JsonConfig<'a>> {
        let mut content = String::new();
        let file        = try!(File::open(file));
        let mut breader = BufReader::new(file);

        try!(breader.read_to_string(&mut content));

        Ok(try!(json::decode(&content)))
    }

    /// Save configuration into a given file.
    fn save(&self, file: &str) -> Result<()> {
        let content     = try!(json::encode(self));
        let file        = try!(File::create(file));
        let mut bwriter = BufWriter::new(file);

        try!(bwriter.write(content.as_bytes()));

        Ok(())
    }
}

impl<'a> Display for JsonConfig<'a> {
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        let content = try!(json::encode(self)
            .or(Err(fmt::Error)));
        f.write_str(&content)
    }
}

/// Arrow configuration.
#[derive(Debug, Clone)]
pub struct ArrowConfig {
    uuid:      Uuid,
    passwd:    Uuid,
    version:   usize,
    svc_table: ServiceTable,
}

impl ArrowConfig {
    /// Create a new empty Arrow configuration.
    pub fn new() -> ArrowConfig {
        ArrowConfig {
            uuid:      Uuid::new_v4(),
            passwd:    Uuid::new_v4(),
            version:   0,
            svc_table: ServiceTable::new()
        }
    }

    /// Get Arrow Client UUID.
    pub fn uuid(&self) -> [u8; 16] {
        self.uuid.as_bytes()
            .clone()
    }

    /// Get formatted Arrow Client UUID.
    pub fn uuid_string(&self) -> String {
        format!("{}", self.uuid.hyphenated())
    }

    /// Get Arrow Client password.
    pub fn password(&self) -> [u8; 16] {
        self.passwd.as_bytes()
            .clone()
    }

    /// Get current configuration version.
    pub fn version(&self) -> usize {
        self.version
    }

    /// Get service according to its ID from the underlaying service table.
    pub fn get(&self, id: u16) -> Option<Service> {
        self.svc_table.get(id)
    }

    /// Add a new service into the underlaying service table.
    pub fn add(&mut self, svc: Service) -> Option<u16> {
        self.svc_table.add(svc)
    }

    /// Add a new static service (i.e. manually added).
    pub fn add_static(&mut self, svc: Service) -> Option<u16> {
        self.svc_table.add_static(svc)
    }

    /// Update active flags of all services.
    pub fn update_active_services(&mut self) -> bool {
        self.svc_table.update_active_services()
    }

    /// Get all active services.
    pub fn active_services(&self) -> Vec<Service> {
        self.svc_table.active_services()
    }

    /// Increment version of this config.
    pub fn bump_version(&mut self) {
        self.version += 1;
    }

    /// Get the underlaying service table.
    pub fn service_table(&self) -> &ServiceTable {
        &self.svc_table
    }

    /// Set contents of the service table to a given value.
    pub fn reinit(&mut self, svc_table: ServiceTable) {
        self.svc_table = svc_table
    }

    /// Load configuration from a given file.
    pub fn load(file: &str) -> Result<ArrowConfig> {
        let json      = try!(JsonConfig::load(file));
        let uuid      = try!(Uuid::parse_str(&json.uuid));
        let passwd    = try!(Uuid::parse_str(&json.passwd));
        let svc_table = json.svc_table.into_owned();

        let res = ArrowConfig {
            uuid:      uuid,
            passwd:    passwd,
            version:   json.version,
            svc_table: svc_table
        };

        Ok(res)
    }

    /// Save configuration into a given file.
    pub fn save(&self, file: &str) -> Result<()> {
        let json = JsonConfig::new(
            format!("{}", self.uuid.hyphenated()),
            format!("{}", self.passwd.hyphenated()),
            self.version,
            &self.svc_table);

        json.save(file)
    }
}

impl Display for ArrowConfig {
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        let json = JsonConfig::new(
            format!("{}", self.uuid.hyphenated()),
            format!("{}", self.passwd.hyphenated()),
            self.version,
            &self.svc_table);

        json.fmt(f)
    }
}

/// Application context.
#[derive(Debug, Clone)]
pub struct AppContext {
    /// Arrow Client configuration.
    pub config:          ArrowConfig,
    /// Scanning state indicator.
    pub scanning:        bool,
    /// Diagnostic mode indicator.
    pub diagnostic_mode: bool,
    /// Service discovery enabler.
    pub discovery:       bool,
    /// Last report from the network scanner.
    pub scan_report:     ScanReport,
}

impl AppContext {
    /// Create a new application context.
    pub fn new(config: ArrowConfig) -> AppContext {
        AppContext {
            config:          config,
            scanning:        false,
            diagnostic_mode: false,
            discovery:       false,
            scan_report:     ScanReport::new()
        }
    }
}*/
