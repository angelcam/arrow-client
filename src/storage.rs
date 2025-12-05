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
    fs::File,
    io::{self, Write},
    path::{Path, PathBuf},
    process,
};

#[cfg(feature = "discovery")]
use std::io::{BufRead, BufReader};

use serde_lite::{Deserialize, Intermediate, Serialize};
use tokio_native_tls::native_tls::{Certificate, TlsConnectorBuilder};

use crate::{
    config::{PersistentConfig, PublicIdentity},
    context::ConnectionState,
};

/// Arrow client storage.
pub trait Storage {
    /// Save a given persistent configuration.
    fn save_configuration(&mut self, config: &PersistentConfig) -> io::Result<()>;

    /// Create a new empty configuration.
    fn create_configuration(&mut self) -> io::Result<PersistentConfig> {
        Ok(PersistentConfig::new())
    }

    /// Load persistent configuration.
    fn load_configuration(&mut self) -> io::Result<PersistentConfig>;

    /// Save connection state.
    fn save_connection_state(&mut self, _: ConnectionState) -> io::Result<()> {
        Ok(())
    }

    /// Load a list of RTSP paths for the device discovery.
    fn load_rtsp_paths(&mut self) -> io::Result<Vec<String>> {
        Ok(Vec::new())
    }

    /// Load a list of MJPEG paths for the device discovery.
    fn load_mjpeg_paths(&mut self) -> io::Result<Vec<String>> {
        Ok(Vec::new())
    }

    /// Load CA certificates.
    fn load_ca_certificates(
        &mut self,
        ssl_connector_builder: &mut TlsConnectorBuilder,
    ) -> io::Result<()>;
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

    /// Build the storage.
    pub fn build(self) -> DefaultStorage {
        DefaultStorage {
            config_file: self.config_file,
            config_skeleton_file: self.config_skeleton_file,
            connection_state_file: self.connection_state_file,
            identity_file: self.identity_file,
            rtsp_paths_file: self.rtsp_paths_file,
            mjpeg_paths_file: self.mjpeg_paths_file,
            ca_cert_files: self.ca_certificates,
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
    _lock_file: Option<File>,
}

impl DefaultStorage {
    /// Get a builder for the file based storage and set a given path to the configuration file.
    pub fn builder<T, L>(config_file: T, lock_file: Option<L>) -> io::Result<DefaultStorageBuilder>
    where
        PathBuf: From<T>,
        L: AsRef<Path>,
    {
        let lock_file = lock_file
            .as_ref()
            .map(|path| path.as_ref())
            .map(|path| {
                create_lock_file(path).map_err(|_| {
                    io::Error::other(format!(
                        "unable to acquire an exclusive lock on \"{}\"",
                        path.display()
                    ))
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
            lock_file,
        };

        Ok(res)
    }
}

impl Storage for DefaultStorage {
    fn save_configuration(&mut self, config: &PersistentConfig) -> io::Result<()> {
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

    fn load_configuration(&mut self) -> io::Result<PersistentConfig> {
        // read config skeleton
        let config_skeleton = self.config_skeleton_file.as_ref().and_then(|file| {
            load_configuration_file(file)
                .inspect_err(|err| {
                    warn!(
                        "unable to read configuration file skeleton \"{}\" ({})",
                        file.display(),
                        err
                    )
                })
                .ok()
        });

        // read config
        let config = load_configuration_file(&self.config_file)
            .inspect_err(|err| {
                warn!(
                    "unable to read configuration file \"{}\" ({})",
                    self.config_file.display(),
                    err
                )
            })
            .ok();

        let config_skeleton_exists = config_skeleton.is_some();

        // get the persistent config, if there is no config, use the skeleton,
        // if there is no skeleton, create a new config
        let config = config
            .or(config_skeleton)
            .map(Ok)
            .unwrap_or_else(|| self.create_configuration())?;

        // if there is no skeleton, create one from the config
        if !config_skeleton_exists && let Some(file) = self.config_skeleton_file.as_ref() {
            let config_skeleton = config.to_skeleton();

            info!(
                "creating configuration file skeleton \"{}\"",
                file.display()
            );

            if let Err(err) = save_configuration_file(&config_skeleton, file) {
                warn!(
                    "unable to create configuration file skeleton \"{}\" ({})",
                    file.display(),
                    err
                );
            }
        }

        // create identity file
        if let Some(file) = self.identity_file.as_ref() {
            let identity = config.to_identity();

            if let Err(err) = save_identity_file(&identity, file) {
                warn!(
                    "unable to create identity file \"{}\" ({})",
                    file.display(),
                    err
                );
            }
        }

        Ok(config)
    }

    fn save_connection_state(&mut self, state: ConnectionState) -> io::Result<()> {
        if let Some(file) = self.connection_state_file.as_ref() {
            let mut file = File::create(file)?;

            writeln!(&mut file, "{}", state)?;
        }

        Ok(())
    }

    fn load_rtsp_paths(&mut self) -> io::Result<Vec<String>> {
        if let Some(file) = self.rtsp_paths_file.as_ref() {
            load_paths(file)
        } else {
            Ok(Vec::new())
        }
    }

    fn load_mjpeg_paths(&mut self) -> io::Result<Vec<String>> {
        if let Some(file) = self.mjpeg_paths_file.as_ref() {
            load_paths(file)
        } else {
            Ok(Vec::new())
        }
    }

    fn load_ca_certificates(
        &mut self,
        ssl_connector_builder: &mut TlsConnectorBuilder,
    ) -> io::Result<()> {
        for path in &self.ca_cert_files {
            if let Err(err) = ssl_connector_builder.load_ca_certificates(path) {
                warn!(
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
trait TlsConnectorBuilderExt {
    /// Load all CA certificates from a given path.
    fn load_ca_certificates<P>(&mut self, path: P) -> io::Result<()>
    where
        P: AsRef<Path>;

    /// Load a given CA certificate file.
    fn load_ca_certificate<P>(&mut self, path: P) -> io::Result<()>
    where
        P: AsRef<Path>;
}

impl TlsConnectorBuilderExt for TlsConnectorBuilder {
    fn load_ca_certificates<P>(&mut self, path: P) -> Result<(), io::Error>
    where
        P: AsRef<Path>,
    {
        // helper function to avoid expensive monomorphization
        fn inner(path: &Path, builder: &mut TlsConnectorBuilder) -> io::Result<()> {
            if path.is_dir() {
                for entry in path.read_dir()? {
                    inner(&entry?.path(), builder)?;
                }
            } else if is_cert_file(path) {
                builder.load_ca_certificate(path)?;
            }

            Ok(())
        }

        inner(path.as_ref(), self)
    }

    fn load_ca_certificate<P>(&mut self, path: P) -> io::Result<()>
    where
        P: AsRef<Path>,
    {
        // helper function to avoid expensive monomorphization
        fn inner(path: &Path, builder: &mut TlsConnectorBuilder) -> io::Result<()> {
            let content = std::fs::read(path)?;

            let res = if content.starts_with(b"-----BEGIN ") {
                Certificate::from_pem(&content)
            } else {
                Certificate::from_der(&content)
            };

            let cert = res.map_err(|_| io::Error::other("invalid CA certificate"))?;

            builder.add_root_certificate(cert);

            Ok(())
        }

        inner(path.as_ref(), self)
    }
}

/// Check if a given file is a certificate file.
fn is_cert_file<P>(path: P) -> bool
where
    P: AsRef<Path>,
{
    // helper function to avoid expensive monomorphization
    fn inner(path: &Path) -> bool {
        if let Some(ext) = path.extension()
            && let Some(ext) = ext.to_str()
        {
            return ext.eq_ignore_ascii_case("der")
                || ext.eq_ignore_ascii_case("cer")
                || ext.eq_ignore_ascii_case("crt")
                || ext.eq_ignore_ascii_case("pem");
        }

        false
    }

    inner(path.as_ref())
}

/// Create a lock file.
fn create_lock_file<P>(path: P) -> Result<File, io::Error>
where
    P: AsRef<Path>,
{
    // helper function to avoid expensive monomorphization
    fn inner(path: &Path) -> io::Result<File> {
        let mut file = File::create(path)?;

        file.try_lock()?;

        writeln!(file, "{}", process::id())?;

        file.flush()?;
        file.sync_all()?;

        Ok(file)
    }

    inner(path.as_ref())
}

/// Helper function for loading persistent config.
fn load_configuration_file<P>(file: P) -> Result<PersistentConfig, io::Error>
where
    P: AsRef<Path>,
{
    // helper function to avoid expensive monomorphization
    fn inner(file: &Path) -> io::Result<PersistentConfig> {
        let file = File::open(file)?;

        let intermediate = serde_json::from_reader::<_, Intermediate>(file)
            .map_err(|err| io::Error::other(format!("unable to parse configuration: {err}")))?;

        PersistentConfig::deserialize(&intermediate).map_err(io::Error::other)
    }

    inner(file.as_ref())
}

/// Helper function for saving persistent config.
fn save_configuration_file<P>(config: &PersistentConfig, file: P) -> io::Result<()>
where
    P: AsRef<Path>,
{
    // helper function to avoid expensive monomorphization
    fn inner(file: &Path, config: &PersistentConfig) -> io::Result<()> {
        let intermediate = config
            .serialize()
            .expect("unable to serialize persistent configuration");

        save_json_file(file, &intermediate)
    }

    inner(file.as_ref(), config)
}

/// Helper function for saving client public identity.
fn save_identity_file<P>(identity: &PublicIdentity, file: P) -> io::Result<()>
where
    P: AsRef<Path>,
{
    // helper function to avoid expensive monomorphization
    fn inner(file: &Path, identity: &PublicIdentity) -> io::Result<()> {
        let intermediate = identity
            .serialize()
            .expect("unable to serialize public identity");

        save_json_file(file, &intermediate)
    }

    inner(file.as_ref(), identity)
}

/// Save a given value as JSON into a given file.
fn save_json_file<P>(file: P, value: &Intermediate) -> io::Result<()>
where
    P: AsRef<Path>,
{
    // helper function to avoid expensive monomorphization
    fn inner(file: &Path, value: &Intermediate) -> io::Result<()> {
        let file = File::create(file)?;

        serde_json::to_writer(file, value).map_err(io::Error::other)
    }

    inner(file.as_ref(), value)
}

/// Helper function for loading all path variants from a given file.
#[cfg(feature = "discovery")]
fn load_paths<P>(file: P) -> io::Result<Vec<String>>
where
    P: AsRef<Path>,
{
    // helper function to avoid expensive monomorphization
    fn inner(file: &Path) -> io::Result<Vec<String>> {
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

    inner(file.as_ref())
}

/// Helper function for loading all path variants from a given file.
#[cfg(not(feature = "discovery"))]
#[allow(clippy::unnecessary_wraps)]
fn load_paths<P>(_: P) -> io::Result<Vec<String>>
where
    P: AsRef<Path>,
{
    Ok(Vec::new())
}
