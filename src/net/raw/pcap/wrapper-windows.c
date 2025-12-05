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

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define WIN32
#define HAVE_REMOTE

#include <pcap.h>

#include "wrapper.h"

int pcap_wrapper__open(Wrapper* wrapper) {
    struct bpf_program filter;
    char* error_buffer;
    char* device_fmt = "rpcap://\\Device\\NPF_%s";
    char* device;
    size_t device_len;
    int ret;

    if (wrapper->h) {
        return pcap_wrapper__set_error(wrapper, EINVAL, NULL);
    }

    device_len = strlen(device_fmt) + strlen(wrapper->device) + 1;
    device = malloc(device_len);
    if (!device) {
        return pcap_wrapper__set_error(wrapper, ENOMEM, NULL);
    }
    snprintf(device, device_len, device_fmt, wrapper->device);

    if (wrapper->error_buffer_size < PCAP_ERRBUF_SIZE) {
        error_buffer = malloc(PCAP_ERRBUF_SIZE);
        if (!error_buffer) {
            return pcap_wrapper__set_error(wrapper, ENOMEM, NULL);
        }
        free(wrapper->error_buffer);
        wrapper->error_buffer = error_buffer;
        wrapper->error_buffer_size = PCAP_ERRBUF_SIZE;
    }

    wrapper->h = (void*)pcap_open(
        device,
        wrapper->max_packet_size,
        PCAP_OPENFLAG_PROMISCUOUS,
        wrapper->read_timeout,
        NULL,
        wrapper->error_buffer);

    free(device);

    if (!wrapper->h) {
        return EINVAL; // note: the error string was set by pcap_open
    }

    if (wrapper->filter) {
        if ((ret = pcap_compile(wrapper->h, &filter, wrapper->filter, 1, 0)) < 0) {
            return pcap_wrapper__set_error(wrapper, ret, pcap_geterr(wrapper->h));
        }

        if ((ret = pcap_setfilter(wrapper->h, &filter)) != 0) {
            pcap_wrapper__set_error(wrapper, ret, pcap_geterr(wrapper->h));
        }

        pcap_freecode(&filter);

        return ret;
    }

    return 0;
}

void pcap_wrapper__close(Wrapper* wrapper) {
    if (wrapper->h) {
        pcap_close(wrapper->h);
    }

    wrapper->h = NULL;
}

typedef struct PacketCallbackData {
    PacketCallback* callback;
    void* opaque;
} PacketCallbackData;

static void packet_handler(u_char* user, const struct pcap_pkthdr* pkt_header, const u_char* pkt_data) {
    PacketCallbackData* callback_data = (PacketCallbackData*)user;
    PacketCallback* callback = callback_data->callback;

    (*callback)(callback_data->opaque, pkt_data, pkt_header->caplen, pkt_header->len);
}

int pcap_wrapper__read_packet(Wrapper* wrapper, PacketCallback* callback, void* opaque) {
    PacketCallbackData data;
    int ret;

    if (!wrapper->h) {
        return pcap_wrapper__set_error(wrapper, EINVAL, NULL);
    }

    data.callback = callback;
    data.opaque = opaque;

    if ((ret = pcap_dispatch(wrapper->h, 1, &packet_handler, (u_char*)&data)) < 0) {
        return pcap_wrapper__set_error(wrapper, ret, pcap_geterr(wrapper->h));
    }

    return ret;
}

int pcap_wrapper__write_packet(Wrapper* wrapper, const uint8_t* data, size_t size) {
    int ret;

    if (!wrapper->h) {
        return pcap_wrapper__set_error(wrapper, EINVAL, NULL);
    }

    if ((ret = pcap_sendpacket(wrapper->h, data, size)) != 0)  {
        return pcap_wrapper__set_error(wrapper, ret, pcap_geterr(wrapper->h));
    }

    return 0;
}
