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

#include <string.h>
#include <stdlib.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <ifaddrs.h>

#include "devices.h"
#include "devices-utils.h"
#include "utils.h"

static int get_mac_address(struct ifaddrs* ifaddrs, const char* dname, unsigned char* buffer) {
    struct ifaddrs* ifaddr;
    struct sockaddr_dl* link;

    for (ifaddr = ifaddrs; ifaddr; ifaddr = ifaddr->ifa_next) {
        if (!ifaddr->ifa_addr || ifaddr->ifa_addr->sa_family != AF_LINK)
            continue;
        if (strcmp(ifaddr->ifa_name, dname) != 0)
            continue;

        link = (struct sockaddr_dl*)ifaddr->ifa_addr;

        if (link->sdl_type != IFT_ETHER || link->sdl_alen != MAC_ADDR_SIZE)
            continue;

        memcpy(buffer, LLADDR(link), MAC_ADDR_SIZE);

        return 0;
    }

    return -1;
}

static struct net_device * get_device_info(struct ifaddrs* ifaddr, struct ifaddrs* ifaddrs) {
    struct net_device* result = net_new_device();

    if (!result)
        return NULL;

    if (!(result->name = string_dup(ifaddr->ifa_name)))
        goto err;

    if (get_mac_address(ifaddrs, result->name, result->mac_address) != 0)
        goto err;
    if (get_ipv4_record(ifaddr->ifa_addr, result->ipv4_address) != 0)
        goto err;
    if (get_ipv4_record(ifaddr->ifa_netmask, result->ipv4_netmask) != 0)
        goto err;

    return result;

err:
    net_free_device_list(result);

    return NULL;
}

struct net_device * net_find_devices() {
    struct net_device* result = NULL;
    struct net_device* tmp;
    struct ifaddrs* ifaddrs;
    struct ifaddrs* ifaddr;

    if (getifaddrs(&ifaddrs) != 0)
        goto err;

    for (ifaddr = ifaddrs; ifaddr != NULL; ifaddr = ifaddr->ifa_next) {
        if (!ifaddr->ifa_addr || ifaddr->ifa_addr->sa_family != AF_INET)
            continue;

        tmp = get_device_info(ifaddr, ifaddrs);
        if (tmp) {
            tmp->next = result;
            result = tmp;
        }
    }

    freeifaddrs(ifaddrs);

err:
    return result;
}
