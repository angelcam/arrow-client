/*
 * Copyright 2020 Angelcam, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "wrapper.h"

static char* string_dup(const char* s) {
    char* res;
    size_t len;

    if (!s) {
        return NULL;
    }

    len = strlen(s);

    res = malloc(len + 1);
    if (!res) {
        return NULL;
    }

    memcpy(res, s, len);
    res[len] = 0;

    return res;
}

Wrapper* pcap_wrapper__new(const char* device) {
    Wrapper* wrapper = malloc(sizeof(Wrapper));
    if (!wrapper) {
        goto err;
    }
    memset(wrapper, 0, sizeof(Wrapper));

    wrapper->device = string_dup(device);
    if (!wrapper->device) {
        goto err;
    }

    wrapper->max_packet_size = 65536;
    wrapper->read_timeout = 1000;
    wrapper->error_buffer_size = 256;

    wrapper->error_buffer = malloc(wrapper->error_buffer_size);
    if (!wrapper->error_buffer) {
        goto err;
    }
    wrapper->error_buffer[0] = 0;

    return wrapper;

err:
    if (wrapper) {
        pcap_wrapper__free(wrapper);
    }

    return NULL;
}

void pcap_wrapper__free(Wrapper* wrapper) {
    if (wrapper->h) {
        pcap_wrapper__close(wrapper);
    }

    if (wrapper->error_buffer) {
        free(wrapper->error_buffer);
    }

    if (wrapper->device) {
        free(wrapper->device);
    }

    if (wrapper->filter) {
        free(wrapper->filter);
    }

    free(wrapper);
}

const char* pcap_wrapper__get_last_error(const Wrapper* wrapper) {
    return wrapper->error_buffer;
}

static void try_realloc_error_buffer(Wrapper* wrapper, size_t new_size) {
    char* new_buffer = malloc(new_size);

    if (new_buffer) {
        free(wrapper->error_buffer);

        wrapper->error_buffer = new_buffer;
        wrapper->error_buffer_size = new_size;
    }
}

static void copy_error_string(Wrapper* wrapper, const char* s) {
    size_t len = strlen(s);

    if ((len + 1) > wrapper->error_buffer_size) {
        try_realloc_error_buffer(wrapper, len + 1);
    }

    if ((len + 1) > wrapper->error_buffer_size) {
        len = wrapper->error_buffer_size - 1;
    }

    memcpy(wrapper->error_buffer, s, len);
    wrapper->error_buffer[len] = 0;
}

static void copy_errno_description(Wrapper* wrapper, int err) {
#ifdef strerror_s
    size_t len = strerrorlen_s(err);

    if ((len + 1) > wrapper->error_buffer_size) {
        try_realloc_error_buffer(wrapper, len + 1);
    }

    strerror_s(wrapper->error_buffer, wrapper->error_buffer_size, err);
#else
    copy_error_string(wrapper, strerror(err));
#endif
}

int pcap_wrapper__set_error(Wrapper* wrapper, int err, const char* desc) {
    if (desc) {
        copy_error_string(wrapper, desc);
    } else {
        copy_errno_description(wrapper, err);
    }

    return err;
}

int pcap_wrapper__set_filter(Wrapper* wrapper, const char* filter) {
    if (wrapper->filter) {
        free(wrapper->filter);
    }

    wrapper->filter = string_dup(filter);
    if (!wrapper->filter) {
        return ENOMEM;
    }

    return 0;
}

void pcap_wrapper__set_max_packet_length(Wrapper* wrapper, size_t max_packet_size) {
    wrapper->max_packet_size = max_packet_size;
}

void pcap_wrapper__set_read_timeout(Wrapper* wrapper, uint64_t read_timeout) {
    wrapper->read_timeout = read_timeout;
}
