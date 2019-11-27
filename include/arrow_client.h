#ifndef ARROW_CLIENT_H
#define ARROW_CLIENT_H

typedef void ArrowClient;
typedef void JoinHandle;
typedef void Config;
typedef void Storage;
typedef void CACertStorage;

typedef void (*LogCallback)(
    void *opaque,
    const char *file,
    uint32_t line,
    uint32_t severity,
    const char *msg);
typedef int (*LoadCACertificates)(void *opaque, CACertStorage *cert_storage);
typedef int (*LoadConfiguration)(void *opaque, char **configuration);
typedef int (*FreeConfiguration)(void *opaque, char *configuration);
typedef int (*LoadPaths)(void *opaque, char ***paths, size_t *len);
typedef int (*FreePaths)(void *opaque, char **paths, size_t len);
typedef int (*SaveConfiguration)(void *opaque, const char *configuration);
typedef int (*SaveConnectionState)(void *opaque, int state);

/**
 * Create a new Arrow client from a given config and storage. The function
 * takes ownership of the given config and storage.
 */
ArrowClient* ac__arrow_client__new(
    Config *config,
    Storage *storage,
    const char *arrow_service_address);

/**
 * Free (and close) a given Arrow client.
 */
void ac__arrow_client__free(ArrowClient* client);

/**
 * Start a given Arrow client in the background and return a join handle. The
 * function does nothing if the client has been already started. The returned
 * join handle must be either freed or awaited.
 */
JoinHandle *ac__arrow_client__start(ArrowClient *client);

/**
 * Start a given Arrow client blocking the current thread. The function does
 * nothing if the client has been already started.
 */
void ac__arrow_client__start_blocking(ArrowClient *client);

/**
 * Close a given Arrow client.
 */
void ac__arrow_client__close(ArrowClient* client);

/**
 * Free a given Arrow client join handle.
 */
void ac__arrow_client_join_handle__free(JoinHandle *handle);

/**
 * Await a given Arrow client join handle.
 */
void ac__arrow_client_join_handle__join(JoinHandle *handle);

/**
 * Create a new Arrow client config.
 */
Config *ac__config__new(void);

/**
 * Free the config.
 */
void ac__config__free(Config *config);

/**
 * Set MAC address. The `mac_address` parameter is expected to be a an array
 * of six bytes or NULL.
 */
void ac__config__set_mac_address(Config *config, const uint8_t *mac_address);

/**
 * Set log callback.
 */
void ac__config__set_log_callback(
    Config *config,
    LogCallback callback,
    void *opaque);

/**
 * Enable/disable automatic service discovery.
 */
void ac__config__set_discovery(Config *config, int enabled);

/**
 * Enable/disable verbose mode.
 */
void ac__config__set_verbose(Config *config, int enabled);

/**
 * Enable/disable diagnostic mode.
 */
void ac__config__set_diagnostic_mode(Config *config, int enabled);

/**
 * Create a new storage.
 */
Storage *ac__storage__new(void *opaque);

/**
 * Free the storage.
 */
void ac__storage__free(Storage *storage);

/**
 * Set function for loading CA certificates.
 */
void ac__storage__set_load_ca_certificates_func(
    Storage *storage,
    LoadCACertificates func);

/**
 * Set function for loading client configuration. If the load function responds
 * with NULL configuration, a new configuration will be created automatically.
 */
void ac__storage__set_load_configuration_func(
    Storage *storage,
    LoadConfiguration load,
    FreeConfiguration free);

/**
 * Set function for loading MJPEG paths.
 */
void ac__storage__set_load_mjpeg_paths_func(
    Storage *storage,
    LoadPaths load,
    FreePaths free);

/**
 * Set function for loading RTSP paths.
 */
void ac__storage__set_load_rtsp_paths_func(
    Storage *storage,
    LoadPaths load,
    FreePaths free);

/**
 * Set function for saving client configuration.
 */
void ac__storage__set_save_configuration_func(
    Storage *storage,
    SaveConfiguration func);

/**
 * Set function for saving client connection state.
 */
void ac__storage__set_save_connection_state_func(
    Storage *storage,
    SaveConnectionState func);

/**
 * Load a given CA certificate file.
 */
int ac__ca_cert_storage__load_ca_file(
    CACertStorage *cert_storage,
    const char *file);

/**
 * Load a given DER certificate.
 */
int ac__ca_cert_storage__load_der(
    CACertStorage *cert_storage,
    const uint8_t *der,
    size_t size);

/**
 * Load a given PEM certificate.
 */
int ac__ca_cert_storage__load_pem(
    CACertStorage *cert_storage,
    const uint8_t *pem,
    size_t size);

#endif /* ARROW_CLIENT_H */
