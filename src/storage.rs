// Copyright 2019 Angelcam, Inc.
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

use std::io;
use std::process;

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[cfg(feature = "discovery")]
use std::io::{BufRead, BufReader};

use fs2::FileExt;

use openssl::ssl::SslConnectorBuilder;

use crate::utils;

use crate::config::{PersistentConfig, PublicIdentity};
use crate::context::ConnectionState;
use crate::utils::json::{FromJson, ToJson};
use crate::utils::logger::{BoxLogger, DummyLogger, Logger, Severity};

/// Arrow client storage.
pub trait Storage {
    /// Save a given persistent configuration.
    fn save_configuration(&mut self, config: &PersistentConfig) -> Result<(), io::Error>;

    /// Create a new empty configuration.
    fn create_configuration(&mut self) -> Result<PersistentConfig, io::Error> {
        Ok(PersistentConfig::new())
    }

    /// Load persistent configuration.
    fn load_configuration(&mut self) -> Result<PersistentConfig, io::Error>;

    /// Save connection state.
    fn save_connection_state(&mut self, _: ConnectionState) -> Result<(), io::Error> {
        Ok(())
    }

    /// Load a list of RTSP paths for the device discovery.
    fn load_rtsp_paths(&mut self) -> Result<Vec<String>, io::Error> {
        Ok(Vec::new())
    }

    /// Load a list of MJPEG paths for the device discovery.
    fn load_mjpeg_paths(&mut self) -> Result<Vec<String>, io::Error> {
        Ok(Vec::new())
    }

    /// Load CA certificates.
    fn load_ca_certificates(
        &mut self,
        ssl_connector_builder: &mut SslConnectorBuilder,
    ) -> Result<(), io::Error>;
}

/// Builder for the default client storage.
pub struct DefaultStorageBuilder {
    config_file: PathBuf,
    config_skeleton_file: Option<PathBuf>,
    connection_state_file: Option<PathBuf>,
    identity_file: Option<PathBuf>,
    rtsp_paths_file: Option<PathBuf>,
    mjpeg_paths_file: Option<PathBuf>,
    ca_certificates: Vec<PathBuf>,
    logger: Option<BoxLogger>,
    lock_file: Option<File>,
}

impl DefaultStorageBuilder {
    /// Set path to the config file skeleton.
    pub fn config_skeleton_file<T>(&mut self, file: Option<T>) -> &mut Self
    where
        PathBuf: From<T>,
    {
        self.config_skeleton_file = file.map(PathBuf::from);
        self
    }

    /// Set path to the connection state file.
    pub fn connection_state_file<T>(&mut self, file: Option<T>) -> &mut Self
    where
        PathBuf: From<T>,
    {
        self.connection_state_file = file.map(PathBuf::from);
        self
    }

    /// Set path to the identity file.
    pub fn identity_file<T>(&mut self, file: Option<T>) -> &mut Self
    where
        PathBuf: From<T>,
    {
        self.identity_file = file.map(PathBuf::from);
        self
    }

    /// Set path to the file containing RTSP paths.
    pub fn rtsp_paths_file<T>(&mut self, file: Option<T>) -> &mut Self
    where
        PathBuf: From<T>,
    {
        self.rtsp_paths_file = file.map(PathBuf::from);
        self
    }

    /// Set path to the file containing MJPEG paths.
    pub fn mjpeg_paths_file<T>(&mut self, file: Option<T>) -> &mut Self
    where
        PathBuf: From<T>,
    {
        self.mjpeg_paths_file = file.map(PathBuf::from);
        self
    }

    /// Add a given CA certificate path.
    pub fn add_ca_cerificate<T>(&mut self, path: T) -> &mut Self
    where
        PathBuf: From<T>,
    {
        self.ca_certificates.push(path.into());
        self
    }

    /// Set paths to the CA certificates.
    pub fn ca_certificates<T>(&mut self, paths: T) -> &mut Self
    where
        Vec<PathBuf>: From<T>,
    {
        self.ca_certificates = paths.into();
        self
    }

    /// Set logger.
    pub fn logger(&mut self, logger: BoxLogger) -> &mut Self {
        self.logger = Some(logger);
        self
    }

    /// Build the storage.
    pub fn build(self) -> DefaultStorage {
        let logger = self
            .logger
            .unwrap_or_else(|| BoxLogger::new(DummyLogger::default()));

        DefaultStorage {
            config_file: self.config_file,
            config_skeleton_file: self.config_skeleton_file,
            connection_state_file: self.connection_state_file,
            identity_file: self.identity_file,
            rtsp_paths_file: self.rtsp_paths_file,
            mjpeg_paths_file: self.mjpeg_paths_file,
            ca_cert_files: self.ca_certificates,
            logger,
            _lock_file: self.lock_file,
        }
    }
}

/// Default file-based client storage.
pub struct DefaultStorage {
    config_file: PathBuf,
    config_skeleton_file: Option<PathBuf>,
    connection_state_file: Option<PathBuf>,
    identity_file: Option<PathBuf>,
    rtsp_paths_file: Option<PathBuf>,
    mjpeg_paths_file: Option<PathBuf>,
    ca_cert_files: Vec<PathBuf>,
    logger: BoxLogger,
    _lock_file: Option<File>,
}

impl DefaultStorage {
    /// Get a builder for the file based storage and set a given path to the configuration file.
    pub fn builder<T, L>(
        config_file: T,
        lock_file: Option<L>,
    ) -> Result<DefaultStorageBuilder, io::Error>
    where
        PathBuf: From<T>,
        L: AsRef<Path>,
    {
        let lock_file = lock_file
            .as_ref()
            .map(|lock_file| {
                File::create(lock_file.as_ref())
                    .and_then(|mut lock_file| {
                        lock_file.try_lock_exclusive()?;
                        lock_file.write_fmt(format_args!("{}\n", process::id()))?;
                        lock_file.flush()?;
                        lock_file.sync_all()?;

                        Ok(lock_file)
                    })
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::Other,
                            format!(
                                "unable to acquire an exclusive lock on \"{}\"",
                                lock_file.as_ref().to_string_lossy()
                            ),
                        )
                    })
            })
            .transpose()?;

        let res = DefaultStorageBuilder {
            config_file: config_file.into(),
            config_skeleton_file: None,
            connection_state_file: None,
            identity_file: None,
            rtsp_paths_file: None,
            mjpeg_paths_file: None,
            ca_certificates: Vec::new(),
            logger: None,
            lock_file,
        };

        Ok(res)
    }
}

impl Storage for DefaultStorage {
    fn save_configuration(&mut self, config: &PersistentConfig) -> Result<(), io::Error> {
        save_configuration_file(config, &self.config_file).map_err(|err| {
            io::Error::new(
                err.kind(),
                format!(
                    "unable to create configuration file \"{}\": {}",
                    self.config_file.display(),
                    err
                ),
            )
        })
    }

    fn load_configuration(&mut self) -> Result<PersistentConfig, io::Error> {
        let mut logger = self.logger.clone();

        // read config skeleton
        let config_skeleton = self.config_skeleton_file.as_ref().and_then(|file| {
            utils::result_or_log(
                &mut logger,
                Severity::WARN,
                format!(
                    "unable to read configuration file skeleton \"{}\"",
                    file.to_string_lossy()
                ),
                load_configuration_file(file),
            )
        });

        // read config
        let config = utils::result_or_log(
            &mut logger,
            Severity::WARN,
            format!(
                "unable to read configuration file \"{}\"",
                self.config_file.to_string_lossy()
            ),
            load_configuration_file(&self.config_file),
        );

        let config_skeleton_exists = config_skeleton.is_some();

        // get the persistent config, if there is no config, use the skeleton,
        // if there is no skeleton, create a new config
        let config = config
            .or(config_skeleton)
            .map(Ok)
            .unwrap_or_else(|| self.create_configuration())?;

        // if there is no skeleton, create one from the config
        if !config_skeleton_exists {
            if let Some(file) = self.config_skeleton_file.as_ref() {
                let config_skeleton = config.to_skeleton();

                log_info!(
                    &mut self.logger,
                    "creating configuration file skeleton \"{}\"",
                    file.to_string_lossy()
                );

                utils::result_or_log(
                    &mut logger,
                    Severity::WARN,
                    format!(
                        "unable to create configuration file skeleton \"{}\"",
                        file.to_string_lossy()
                    ),
                    save_configuration_file(&config_skeleton, file),
                );
            }
        }

        // create identity file
        if let Some(file) = self.identity_file.as_ref() {
            let identity = config.to_identity();

            utils::result_or_log(
                &mut logger,
                Severity::WARN,
                format!(
                    "unable to create identity file \"{}\"",
                    file.to_string_lossy()
                ),
                save_identity_file(&identity, file),
            );
        }

        Ok(config)
    }

    fn save_connection_state(&mut self, state: ConnectionState) -> Result<(), io::Error> {
        if let Some(file) = self.connection_state_file.as_ref() {
            let mut file = File::create(file)?;

            writeln!(&mut file, "{}", state)?;
        }

        Ok(())
    }

    fn load_rtsp_paths(&mut self) -> Result<Vec<String>, io::Error> {
        if let Some(file) = self.rtsp_paths_file.as_ref() {
            load_paths(file)
        } else {
            Ok(Vec::new())
        }
    }

    fn load_mjpeg_paths(&mut self) -> Result<Vec<String>, io::Error> {
        if let Some(file) = self.mjpeg_paths_file.as_ref() {
            load_paths(file)
        } else {
            Ok(Vec::new())
        }
    }

    fn load_ca_certificates(
        &mut self,
        ssl_connector_builder: &mut SslConnectorBuilder,
    ) -> Result<(), io::Error> {
        for path in &self.ca_cert_files {
            if let Err(err) = ssl_connector_builder.load_ca_certificates(path) {
                log_warn!(
                    &mut self.logger,
                    "unable to open certificate file/dir \"{}\" ({})",
                    path.display(),
                    err
                );
            }
        }

        Ok(())
    }
}

/// Simple extension to the SslContextBuilder.
trait SslConnectorBuilderExt {
    /// Load all CA certificates from a given path.
    fn load_ca_certificates<P>(&mut self, path: P) -> Result<(), io::Error>
    where
        P: AsRef<Path>;
}

impl SslConnectorBuilderExt for SslConnectorBuilder {
    fn load_ca_certificates<P>(&mut self, path: P) -> Result<(), io::Error>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();

        if path.is_dir() {
            let dir = path.read_dir()?;

            for entry in dir {
                let path = entry?.path();

                self.load_ca_certificates(&path)?;
            }
        } else if is_cert_file(path) {
            self.set_ca_file(path)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("{}", err)))?;
        }

        Ok(())
    }
}

/// Check if a given file is a certificate file.
fn is_cert_file<P>(path: P) -> bool
where
    P: AsRef<Path>,
{
    let path = path.as_ref();

    if let Some(ext) = path.extension() {
        let ext = ext.to_string_lossy();

        ext.eq_ignore_ascii_case("der")
            || ext.eq_ignore_ascii_case("cer")
            || ext.eq_ignore_ascii_case("crt")
            || ext.eq_ignore_ascii_case("pem")
    } else {
        false
    }
}

/// Helper function for loading persistent config.
fn load_configuration_file<P>(file: P) -> Result<PersistentConfig, io::Error>
where
    P: AsRef<Path>,
{
    let mut file = File::open(file)?;
    let mut data = String::new();

    file.read_to_string(&mut data)?;

    let object = json::parse(&data).map_err(|err| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("unable to parse configuration: {}", err),
        )
    })?;

    let config = PersistentConfig::from_json(object)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;

    Ok(config)
}

/// Helper function for saving persistent config.
fn save_configuration_file<P>(config: &PersistentConfig, file: P) -> Result<(), io::Error>
where
    P: AsRef<Path>,
{
    let mut file = File::create(file)?;

    config.to_json().write(&mut file)?;

    Ok(())
}

/// Helper function for saving client public identity.
fn save_identity_file<P>(identity: &PublicIdentity, file: P) -> Result<(), io::Error>
where
    P: AsRef<Path>,
{
    let mut file = File::create(file)?;

    identity.to_json().write(&mut file)?;

    Ok(())
}

/// Helper function for loading all path variants from a given file.
#[cfg(feature = "discovery")]
fn load_paths<P>(file: P) -> Result<Vec<String>, io::Error>
where
    P: AsRef<Path>,
{
    let file = File::open(file)?;
    let breader = BufReader::new(file);

    let mut paths = Vec::new();

    for line in breader.lines() {
        let path = line?;
        if !path.starts_with('#') {
            paths.push(path);
        }
    }

    Ok(paths)
}

/// Helper function for loading all path variants from a given file.
#[cfg(not(feature = "discovery"))]
#[allow(clippy::unnecessary_wraps)]
fn load_paths<P>(_: P) -> Result<Vec<String>, io::Error>
where
    P: AsRef<Path>,
{
    Ok(Vec::new())
}
