/*
 * Copyright 2015 click2stream, Inc.
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <ifaddrs.h>

#include "devices.h"
#include "devices-utils.h"
#include "utils.h"

static int get_mac_address(const char* dname, struct ifaddrs* ifaddrs, unsigned char* buffer) {
    struct ifaddrs* cur;

    for (cur = ifaddrs; cur; cur = cur->ifa_next) {
        if (cur->ifa_addr && (cur->ifa_addr->sa_family == AF_LINK) &&
                (strcmp(cur->ifa_name, dname) == 0)) {
            struct sockaddr_dl* sdl = (struct sockaddr_dl*)cur->ifa_addr;
            memcpy(buffer, LLADDR(sdl), sdl->sdl_alen);
            return 0;
        }
    }
    return -1;
}

static struct net_device * get_device_info(struct ifaddrs* ifaddr, struct ifaddrs* ifaddrs) {
    struct net_device* result = net_new_device();

    if (!result)
        return NULL;

    if (!(result->name = string_dup(ifaddr->ifa_name)))
        goto err;

    if (get_mac_address(result->name, ifaddrs, result->mac_address) != 0)
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
