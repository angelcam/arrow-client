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

#include "devices.h"

struct net_device* net_new_device() {
    return calloc(1, sizeof(struct net_device));
}

void net_free_device_list(struct net_device* dev) {
    struct net_device* tmp;

    while (dev) {
        tmp = dev;
        dev = dev->next;
        if (tmp->name) {
            free(tmp->name);
        }
        free(tmp);
    }
}

const char* net_get_name(const struct net_device* dev) {
    return dev->name;
}

const unsigned char* net_get_ipv4_address(const struct net_device* dev) {
    return dev->ipv4_address;
}

const unsigned char* net_get_ipv4_netmask(const struct net_device* dev) {
    return dev->ipv4_netmask;
}

const unsigned char* net_get_mac_address(const struct net_device* dev) {
    return dev->mac_address;
}

const struct net_device* net_get_next_device(const struct net_device* dev) {
    return dev->next;
}

size_t net_get_mac_addr_size() {
    return MAC_ADDR_SIZE;
}

size_t net_get_ipv4_addr_size() {
    return IPV4_ADDR_SIZE;
}
