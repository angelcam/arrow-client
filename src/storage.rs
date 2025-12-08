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
    io::{self, Write},
    path::{Path, PathBuf},
    process,
};

use serde_lite::{Deserialize, Intermediate, Serialize};
use tokio::fs::File;

use crate::{
    config::{PersistentConfig, PublicIdentity},
    context::ConnectionState,
    tls::TlsConnectorBuilder,
};

/// Arrow client storage.
#[trait_variant::make(Send)]
pub trait Storage {
    /// Save a given persistent configuration.
    async fn save_configuration(&self, config: &PersistentConfig) -> io::Result<()>;

    /// Create a new empty configuration.
    fn create_configuration(&self) -> PersistentConfig {
        PersistentConfig::new()
    }

    /// Load persistent configuration.
    async fn load_configuration(&self) -> io::Result<PersistentConfig>;

    /// Save connection state.
    fn save_connection_state(
        &self,
        _: ConnectionState,
    ) -> impl Future<Output = io::Result<()>> + Send {
        async { Ok(()) }
    }

    /// Load a list of RTSP paths for the device discovery.
    fn load_rtsp_paths(&self) -> impl Future<Output = io::Result<Vec<String>>> + Send {
        async { Ok(Vec::new()) }
    }

    /// Load a list of MJPEG paths for the device discovery.
    fn load_mjpeg_paths(&self) -> impl Future<Output = io::Result<Vec<String>>> + Send {
        async { Ok(Vec::new()) }
    }

    /// Load CA certificates.
    async fn load_ca_certificates(
        &self,
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
    pub fn add_ca_certificate<T>(&mut self, path: T) -> &mut Self
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
    pub async fn builder<T, L>(
        config_file: T,
        lock_file: Option<L>,
    ) -> io::Result<DefaultStorageBuilder>
    where
        PathBuf: From<T>,
        L: AsRef<Path>,
    {
        let lock_file = if let Some(lock_file) = lock_file {
            let path = lock_file.as_ref();

            create_lock_file(path).await.map(Some).map_err(|_| {
                io::Error::other(format!(
                    "unable to acquire an exclusive lock on \"{}\"",
                    path.display()
                ))
            })?
        } else {
            None
        };

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
    async fn save_configuration(&self, config: &PersistentConfig) -> io::Result<()> {
        save_configuration_file(config, &self.config_file)
            .await
            .map_err(|err| {
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

    async fn load_configuration(&self) -> io::Result<PersistentConfig> {
        // read config skeleton
        let config_skeleton = if let Some(file) = self.config_skeleton_file.as_ref() {
            load_configuration_file(file)
                .await
                .inspect_err(|err| {
                    warn!(
                        "unable to read configuration file skeleton \"{}\" ({})",
                        file.display(),
                        err
                    )
                })
                .ok()
        } else {
            None
        };

        // read config
        let config = load_configuration_file(&self.config_file)
            .await
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
            .unwrap_or_else(|| self.create_configuration());

        // if there is no skeleton, create one from the config
        if !config_skeleton_exists && let Some(file) = self.config_skeleton_file.as_ref() {
            let config_skeleton = config.to_skeleton();

            info!(
                "creating configuration file skeleton \"{}\"",
                file.display()
            );

            if let Err(err) = save_configuration_file(&config_skeleton, file).await {
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

            if let Err(err) = save_identity_file(&identity, file).await {
                warn!(
                    "unable to create identity file \"{}\" ({})",
                    file.display(),
                    err
                );
            }
        }

        Ok(config)
    }

    async fn save_connection_state(&self, state: ConnectionState) -> io::Result<()> {
        if let Some(file) = self.connection_state_file.as_ref() {
            tokio::fs::write(file, format!("{}\n", state)).await?;
        }

        Ok(())
    }

    async fn load_rtsp_paths(&self) -> io::Result<Vec<String>> {
        if let Some(file) = self.rtsp_paths_file.as_ref() {
            load_paths(file).await
        } else {
            Ok(Vec::new())
        }
    }

    async fn load_mjpeg_paths(&self) -> io::Result<Vec<String>> {
        if let Some(file) = self.mjpeg_paths_file.as_ref() {
            load_paths(file).await
        } else {
            Ok(Vec::new())
        }
    }

    async fn load_ca_certificates(
        &self,
        ssl_connector_builder: &mut TlsConnectorBuilder,
    ) -> io::Result<()> {
        for path in &self.ca_cert_files {
            if let Err(err) = ssl_connector_builder.load_ca_certificates(path).await {
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
    async fn load_ca_certificates(&mut self, path: &Path) -> io::Result<()>;

    /// Load a given CA certificate file.
    async fn load_ca_certificate(&mut self, path: &Path) -> io::Result<()>;
}

impl TlsConnectorBuilderExt for TlsConnectorBuilder {
    async fn load_ca_certificates(&mut self, path: &Path) -> io::Result<()> {
        let meta = tokio::fs::metadata(path).await?;

        if meta.is_dir() {
            let mut entries = tokio::fs::read_dir(path).await?;

            while let Some(entry) = entries.next_entry().await? {
                let this = &mut *self;

                let future =
                    Box::pin(async move { this.load_ca_certificates(&entry.path()).await });

                future.await?;
            }
        } else if is_cert_file(path) {
            self.load_ca_certificate(path).await?;
        }

        Ok(())
    }

    async fn load_ca_certificate(&mut self, path: &Path) -> io::Result<()> {
        self.add_root_certificate(path).await
    }
}

/// Check if a given file is a certificate file.
fn is_cert_file(path: &Path) -> bool {
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

/// Create a lock file.
async fn create_lock_file(path: &Path) -> io::Result<File> {
    let path = path.to_path_buf();

    let blocking = tokio::task::spawn_blocking(|| {
        let mut file = std::fs::File::create(path)?;

        file.try_lock()?;

        writeln!(file, "{}", process::id())?;

        file.flush()?;
        file.sync_all()?;

        Ok(file.into())
    });

    blocking
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::Interrupted))?
}

/// Helper function for loading persistent config.
async fn load_configuration_file(file: &Path) -> io::Result<PersistentConfig> {
    let content = tokio::fs::read(file).await?;

    let intermediate = serde_json::from_slice::<Intermediate>(&content)
        .map_err(|err| io::Error::other(format!("unable to parse configuration: {err}")))?;

    PersistentConfig::deserialize(&intermediate).map_err(io::Error::other)
}

/// Helper function for saving persistent config.
async fn save_configuration_file(config: &PersistentConfig, file: &Path) -> io::Result<()> {
    let intermediate = config
        .serialize()
        .expect("unable to serialize persistent configuration");

    save_json_file(file, &intermediate).await
}

/// Helper function for saving client public identity.
async fn save_identity_file(identity: &PublicIdentity, file: &Path) -> io::Result<()> {
    let intermediate = identity
        .serialize()
        .expect("unable to serialize public identity");

    save_json_file(file, &intermediate).await
}

/// Save a given value as JSON into a given file.
async fn save_json_file(file: &Path, value: &Intermediate) -> io::Result<()> {
    let content = serde_json::to_vec(value).map_err(io::Error::other)?;

    tokio::fs::write(file, content).await
}

/// Helper function for loading all path variants from a given file.
#[cfg(feature = "discovery")]
async fn load_paths(file: &Path) -> io::Result<Vec<String>> {
    let content = tokio::fs::read_to_string(file).await?;

    let mut paths = Vec::new();

    for line in content.lines() {
        if !line.starts_with('#') {
            paths.push(String::from(line));
        }
    }

    Ok(paths)
}

/// Helper function for loading all path variants from a given file.
#[cfg(not(feature = "discovery"))]
#[allow(clippy::unnecessary_wraps)]
async fn load_paths(_: &Path) -> io::Result<Vec<String>> {
    Ok(Vec::new())
}
