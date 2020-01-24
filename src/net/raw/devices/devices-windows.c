/*
 * Copyright 2020 click2stream, Inc.
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

#include <winsock2.h>
#include <iphlpapi.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "IPHLPAPI.lib")

#include "devices.h"
#include "utils.h"

static const IP_ADAPTER_UNICAST_ADDRESS* find_ipv4_unicast_address(const IP_ADAPTER_ADDRESSES* adapter) {
    const IP_ADAPTER_UNICAST_ADDRESS* address = adapter->FirstUnicastAddress;

    while (address && address->Address.lpSockaddr->sa_family != AF_INET) {
        address = address->Next;
    }

    return address;
}

static void set_ipv4_netmask(int prefix_length, unsigned char* buffer) {
    size_t mask_index = 0;

    while (prefix_length > 0 && mask_index < IPV4_ADDR_SIZE) {
        buffer[mask_index] = ~((unsigned int)0xff >> prefix_length);
        prefix_length -= 8;
        mask_index++;
    }
}

static net_device* get_device_info(const IP_ADAPTER_ADDRESSES* adapter) {
    const IP_ADAPTER_UNICAST_ADDRESS* ipv4_address;

    struct net_device* res = net_new_device();

    if (!res) {
        return NULL;
    }

    res->name = string_dup(adapter->AdapterName);
    
    memcpy(res->mac_address, adapter->PhysicalAddress, MAC_ADDR_SIZE);

    ipv4_address = find_ipv4_unicast_address(adapter);

    get_ipv4_record(ipv4_address->Address.lpSockaddr, res->ipv4_address);
    set_ipv4_netmask(ipv4_address->OnLinkPrefixLength, res->ipv4_netmask);

    return res;
}

net_device* add_device_info(net_device* device_list, const IP_ADAPTER_ADDRESSES* adapter) {
    net_device* res = get_device_info(adapter);

    if (device_list) {
        device_list->next = res;
    }

    return res;
}

struct net_device* net_find_devices() {
    PIP_ADAPTER_ADDRESSES adapters;
    PIP_ADAPTER_ADDRESSES adapter;

    ULONG adapters_size = sizeof(IP_ADAPTER_ADDRESSES);

    net_device* devices = NULL;
    net_device* last_device = NULL;

    adapters = malloc(adapters_size);

    if (!adapters) {
        goto err;
    }

    if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, adapters, &adapters_size) == ERROR_BUFFER_OVERFLOW) {
        free(adapters);

        adapters = malloc(adapters_size);

        if (!adapters) {
            goto err;
        }
    }

    if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, adapters, &adapters_size) == NO_ERROR) {
        adapter = adapters;

        while (adapter) {
            if (adapter->IfType == IF_TYPE_ETHERNET_CSMACD || adapter->IfType == IF_TYPE_IEEE80211) {
                if (adapter->PhysicalAddressLength == MAC_ADDR_SIZE && find_ipv4_unicast_address(adapter)) {
                    last_device = add_device_info(last_device, adapter);

                    if (!last_device) {
                        goto err;
                    } else if (!devices) {
                        devices = last_device;
                    }
                }
            }

            adapter = adapter->Next;
        }
    }

    free(adapters);

    return devices;

err:
    if (adapters) {
        free(adapters);
    }

    net_free_device_list(devices);

    return NULL;
}
