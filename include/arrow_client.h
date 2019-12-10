#ifndef ARROW_CLIENT_H
#define ARROW_CLIENT_H

typedef void ArrowClient;
typedef void JoinHandle;
typedef void Logger;
typedef void Config;
typedef void Storage;
typedef void CustomStorageBuilder;
typedef void DefaultStorageBuilder;
typedef void CACertStorage;

typedef void LogCallback(
    void *opaque,
    const char *file,
    uint32_t line,
    uint32_t severity,
    const char *msg);

typedef void ConnectionStateCallback(void* opaque, int state);
typedef void NetworkScannerStateCallback(void* opaque, int state);

typedef int LoadCACertificates(void *opaque, CACertStorage *cert_storage);
typedef int LoadConfiguration(void *opaque, char **configuration);
typedef int LoadPaths(void *opaque, char ***paths, size_t *len);
typedef int SaveConfiguration(void *opaque, const char *configuration);
typedef int SaveConnectionState(void *opaque, int state);

#define CONNECTION_STATE_DISCONNECTED   0
#define CONNECTION_STATE_CONNECTED      1
#define CONNECTION_STATE_UNAUTHORIZED   2

/**
 * Allocate a block of memory with a given size.
 */
void* ac__malloc(size_t size);

/**
 * Free a given block of memory.
 */
void ac__free(void* ptr);

/**
 * Create a new Arrow client from a given config and storage. The function
 * takes ownership of the given config and storage.
 */
ArrowClient* ac__arrow_client__new(
    Config* config,
    Storage* storage,
    const char* arrow_service_address);

/**
 * Free (and close) a given Arrow client.
 */
void ac__arrow_client__free(ArrowClient* client);

/**
 * Start a given Arrow client in the background and return a join handle. The
 * function does nothing if the client has been already started. The returned
 * join handle must be either freed or awaited.
 */
JoinHandle* ac__arrow_client__start(ArrowClient* client);

/**
 * Start a given Arrow client blocking the current thread. The function does
 * nothing if the client has been already started.
 */
void ac__arrow_client__start_blocking(ArrowClient* client);

/**
 * Close a given Arrow client.
 */
void ac__arrow_client__close(ArrowClient* client);

/**
 * Add a given connection state callback.
 */
void ac__arrow_client__add_connection_state_callback(
    ArrowClient* client,
    ConnectionStateCallback* callback,
    void* opaque);

/**
 * Add a given network scanner state callback.
 */
void ac__arrow_client__add_network_scanner_state_callback(
    ArrowClient* client,
    NetworkScannerStateCallback* callback,
    void* opaque);

/**
 * Get Arrow client UUID. The given buffer must have enough space to store at
 * least 16 bytes.
 */
void ac__arrow_client__get_uuid(const ArrowClient* client, uint8_t* uuid);

/**
 * Get MAC address used for Arrow client identification. The given buffer must
 * have enough space to store at least 6 bytes.
 */
void ac__arrow_client__get_mac_address(
    const ArrowClient* client,
    uint8_t* uuid);

/**
 * Free a given join handle.
 */
void ac__join_handle__free(JoinHandle* handle);

/**
 * Await a given join handle. The function takes ownership of the handle.
 */
void ac__join_handle__join(JoinHandle* handle);

/**
 * Create a new Arrow client config.
 */
Config* ac__config__new(void);

/**
 * Free the config.
 */
void ac__config__free(Config* config);

/**
 * Set logger. The function takes ownership of the logger.
 */
void ac__config__set_logger(Config* config, Logger* logger);

/**
 * Set MAC address. The `mac_address` parameter is expected to be a an array
 * of six bytes or NULL.
 */
void ac__config__set_mac_address(Config* config, const uint8_t* mac_address);

/**
 * Enable/disable diagnostic mode.
 */
void ac__config__set_diagnostic_mode(Config* config, int enabled);

/**
 * Enable/disable automatic service discovery.
 */
void ac__config__set_discovery(Config* config, int enabled);

/**
 * Enable/disable verbose mode.
 */
void ac__config__set_verbose(Config* config, int enabled);

/**
 * Create a new logger using a given custom log callback.
 */
Logger* ac__logger__custom(LogCallback* callback, void* opaque);

/**
 * Create a new syslog logger.
 */
Logger* ac__logger__syslog(void);

/**
 * Create a new stderr logger.
 */
Logger* ac__logger__stderr(int pretty);

/**
 * Create a new file logger. The function returns NULL if the log file cannot
 * be open.
 */
Logger* ac__logger__file(const char* path, size_t limit, size_t rotations);

/**
 * Clone a given logger.
 */
Logger* ac__logger__clone(const Logger* logger);

/**
 * Free a give logger.
 */
void ac__logger__free(Logger* logger);

/**
 * Create a new custom storage builder.
 */
CustomStorageBuilder* ac__custom_storage_builder__new(void* opaque);

/**
 * Free the storage.
 */
void ac__custom_storage_builder__free(CustomStorageBuilder* builder);

/**
 * Set function for saving client configuration.
 */
void ac__custom_storage_builder__set_save_configuration_func(
    CustomStorageBuilder* builder,
    SaveConfiguration* func);

/**
 * Set function for loading client configuration. If the load function responds
 * with NULL configuration, a new configuration will be created automatically.
 * The function must allocate the configuration using `ac__malloc()`.
 */
void ac__custom_storage_builder__set_load_configuration_func(
    CustomStorageBuilder* builder,
    LoadConfiguration* load);

/**
 * Set function for saving client connection state.
 */
void ac__custom_storage_builder__set_save_connection_state_func(
    CustomStorageBuilder* builder,
    SaveConnectionState* func);

/**
 * Set function for loading RTSP paths. The function must allocate the paths
 * using `ac__malloc()`.
 */
void ac__custom_storage_builder__set_load_rtsp_paths_func(
    CustomStorageBuilder* builder,
    LoadPaths* load);

/**
 * Set function for loading MJPEG paths. The function must allocate the paths
 * using `ac__malloc()`.
 */
void ac__custom_storage_builder__set_load_mjpeg_paths_func(
    CustomStorageBuilder* builder,
    LoadPaths* load);

/**
 * Set function for loading CA certificates.
 */
void ac__custom_storage_builder__set_load_ca_certificates_func(
    CustomStorageBuilder* builder,
    LoadCACertificates* func);

/**
 * Build the storage. The function takes ownership of the builder.
 */
Storage* ac__custom_storage_builder__build(CustomStorageBuilder* builder);

/**
 * Create a new builder for the default storage. The function takes a path to
 * a configuration file and a path to a lock file. The lock file path may be
 * NULL. The function returns NULL if the lock file cannot be created/locked.
 */
DefaultStorageBuilder* ac__default_storage_builder__new(
    const char* config_file,
    const char* lock_file);

/**
 * Free the builder.
 */
void ac__default_storage_builder__free(DefaultStorageBuilder* builder);

/**
 * Set path for the configuration skeleton file.
 */
void ac__default_storage_builder__set_config_skeleton_file(
    DefaultStorageBuilder* builder,
    const char* file);

/**
 * Set path for the connection state file.
 */
void ac__default_storage_builder__set_connection_state_file(
    DefaultStorageBuilder* builder,
    const char* file);

/**
 * Set path for the identity file.
 */
void ac__default_storage_builder__set_identity_file(
    DefaultStorageBuilder* builder,
    const char* file);

/**
 * Set path for the file containing RTSP paths.
 */
void ac__default_storage_builder__set_rtsp_paths_file(
    DefaultStorageBuilder* builder,
    const char* file);

/**
 * Set path for the file containing MJPEG paths.
 */
void ac__default_storage_builder__set_mjpeg_paths_file(
    DefaultStorageBuilder* builder,
    const char* file);

/**
 * Add a path to a CA certificate.
 */
void ac__default_storage_builder__add_ca_cerificate(
    DefaultStorageBuilder* builder,
    const char* file);

/**
 * Set logger.
 */
void ac__default_storage_builder__set_logger(
    DefaultStorageBuilder* builder,
    Logger* logger);

/**
 * Build the storage. The function takes ownership of the builder.
 */
Storage* ac__default_storage_builder__build(DefaultStorageBuilder* builder);

/**
 * Free a given storage.
 */
void ac__storage__free(Storage* storage);

/**
 * Load a given CA certificate file.
 */
int ac__ca_cert_storage__load_ca_file(
    CACertStorage* cert_storage,
    const char* file);

/**
 * Load a given DER certificate.
 */
int ac__ca_cert_storage__load_der(
    CACertStorage* cert_storage,
    const uint8_t* der,
    size_t size);

/**
 * Load a given PEM certificate.
 */
int ac__ca_cert_storage__load_pem(
    CACertStorage* cert_storage,
    const uint8_t* pem,
    size_t size);

#endif /* ARROW_CLIENT_H */
