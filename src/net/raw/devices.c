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
#include <netinet/in.h>
#include <ifaddrs.h>

#define MAC_ADDR_SIZE       6
#define IPV4_ADDR_SIZE      4

typedef struct net_device {
    char* name;
    unsigned char ipv4_address[IPV4_ADDR_SIZE];
    unsigned char ipv4_netmask[IPV4_ADDR_SIZE];
    unsigned char mac_address[MAC_ADDR_SIZE];
    struct net_device* next;
} net_device;

static char * string_dup(const char* str) {
    char* result;
    size_t len;

    if (!str)
        return NULL;

    len = strlen(str);
    result = malloc(len + 1);
    if (!result)
        return NULL;

    memcpy(result, str, len);
    result[len] = 0;

    return result;
}

static int get_mac_address(int fd, const char* dname, unsigned char* buffer) {
    struct ifreq dconf;

    memset(&dconf, 0, sizeof(dconf));
    strncpy(dconf.ifr_name, dname, IFNAMSIZ);

    if (ioctl(fd, SIOCGIFHWADDR, &dconf) != 0)
        return -1;
    if (dconf.ifr_hwaddr.sa_family != ARPHRD_ETHER)
        return -2;

    memcpy(buffer, dconf.ifr_hwaddr.sa_data, MAC_ADDR_SIZE);

    return 0;
}

static int get_ipv4_record(struct sockaddr *addr, unsigned char* buffer) {
    struct sockaddr_in* inet_addr;

    if (addr->sa_family != AF_INET)
        return -1;

    inet_addr = (struct sockaddr_in*)addr;

    memcpy(buffer, &inet_addr->sin_addr, IPV4_ADDR_SIZE);

    return 0;
}

void net_free_device_list(struct net_device* dev) {
    struct net_device* tmp;
    while (dev) {
        tmp = dev;
        dev = dev->next;
        free(tmp->name);
        free(tmp);
    }
}

static struct net_device * get_device_info(int fd, struct ifaddrs* ifaddrs) {
    struct net_device* result;

    result = malloc(sizeof(net_device));
    if (!result)
        return NULL;

    memset(result, 0, sizeof(net_device));

    if (!(result->name = string_dup(ifaddrs->ifa_name))) {
        free(result);
        return NULL;
    }

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

const char * net_get_name(const struct net_device* dev) {
    return dev->name;
}

const unsigned char * net_get_ipv4_address(const struct net_device* dev) {
    return dev->ipv4_address;
}

const unsigned char * net_get_ipv4_netmask(const struct net_device* dev) {
    return dev->ipv4_netmask;
}

const unsigned char * net_get_mac_address(const struct net_device* dev) {
    return dev->mac_address;
}

const struct net_device * net_get_next_device(const struct net_device* dev) {
    return dev->next;
}

size_t net_get_mac_addr_size() {
    return MAC_ADDR_SIZE;
}

size_t net_get_ipv4_addr_size() {
    return IPV4_ADDR_SIZE;
}
