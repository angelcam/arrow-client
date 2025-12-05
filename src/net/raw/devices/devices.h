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

#ifndef ARROW_CLIENT_DEVICES_H
#define ARROW_CLIENT_DEVICES_H

#define MAC_ADDR_SIZE       6
#define IPV4_ADDR_SIZE      4

typedef struct net_device {
    char* name;
    unsigned char ipv4_address[IPV4_ADDR_SIZE];
    unsigned char ipv4_netmask[IPV4_ADDR_SIZE];
    unsigned char mac_address[MAC_ADDR_SIZE];
    struct net_device* next;
} net_device;

struct net_device* net_new_device();
void net_free_device_list(struct net_device* dev);
struct net_device* net_find_devices();
const char* net_get_name(const struct net_device* dev);
const unsigned char* net_get_ipv4_address(const struct net_device* dev);
const unsigned char* net_get_ipv4_netmask(const struct net_device* dev);
const unsigned char* net_get_mac_address(const struct net_device* dev);
const struct net_device* net_get_next_device(const struct net_device* dev);
size_t net_get_mac_addr_size();
size_t net_get_ipv4_addr_size();

#endif // ARROW_CLIENT_DEVICES_H
