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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <ifaddrs.h>

#include "devices.h"
#include "devices-utils.h"
#include "utils.h"

static int get_mac_address(int fd, const char* dname, unsigned char* buffer) {
    struct ifreq dconf;

    memset(&dconf, 0, sizeof(dconf));
    strncpy(dconf.ifr_name, dname, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &dconf) != 0)
        return -1;
    if (dconf.ifr_hwaddr.sa_family != ARPHRD_ETHER)
        return -2;

    memcpy(buffer, dconf.ifr_hwaddr.sa_data, MAC_ADDR_SIZE);

    return 0;
}

static struct net_device * get_device_info(int fd, struct ifaddrs* ifaddrs) {
    struct net_device* result = net_new_device();

    if (!result)
        return NULL;

    if (!(result->name = string_dup(ifaddrs->ifa_name)))
        goto err;

    if (get_mac_address(fd, result->name, result->mac_address) != 0)
        goto err;
    if (get_ipv4_record(ifaddrs->ifa_addr, result->ipv4_address) != 0)
        goto err;
    if (get_ipv4_record(ifaddrs->ifa_netmask, result->ipv4_netmask) != 0)
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
    int fd;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        return NULL;
    if (getifaddrs(&ifaddrs) != 0)
        goto err;

    for (ifaddr = ifaddrs; ifaddr != NULL; ifaddr = ifaddr->ifa_next) {
        if (!ifaddr->ifa_addr)
            continue;

        tmp = get_device_info(fd, ifaddr);
        if (tmp) {
            tmp->next = result;
            result = tmp;
        }
    }

    freeifaddrs(ifaddrs);

err:
    close(fd);

    return result;
}
