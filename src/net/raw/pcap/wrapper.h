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

#ifndef PCAP_WRAPPER_H
#define PCAP_WRAPPER_H

#include <stdint.h>

typedef struct Wrapper {
    char* device;
    char* filter;
    size_t max_packet_size;
    uint64_t read_timeout;
    char* error_buffer;
    size_t error_buffer_size;
    void* h;
} Wrapper;

typedef void PacketCallback(void* opaque, const uint8_t* data, size_t data_length, size_t packet_length);

Wrapper* pcap_wrapper__new(const char* device);
void pcap_wrapper__free(Wrapper* wrapper);

const char* pcap_wrapper__get_last_error(const Wrapper* wrapper);

int pcap_wrapper__set_error(Wrapper* wrapper, int err, const char* desc);

int pcap_wrapper__set_filter(Wrapper* wrapper, const char* filter);
void pcap_wrapper__set_max_packet_length(Wrapper* wrapper, size_t max_packet_size);
void pcap_wrapper__set_read_timeout(Wrapper* wrapper, uint64_t read_timeout);

int pcap_wrapper__open(Wrapper* wrapper);
void pcap_wrapper__close(Wrapper* wrapper);

int pcap_wrapper__read_packet(Wrapper* wrapper, PacketCallback* callback, void* opaque);
int pcap_wrapper__write_packet(Wrapper* wrapper, const uint8_t* data, size_t size);

#endif // PCAP_WRAPPER_H
