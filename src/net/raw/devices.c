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
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>

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
    if (!str)
        return NULL;
    
    size_t len = strlen(str);
    char* result = malloc(len + 1);
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

static int get_ipv4_record(int fd, unsigned long addr_type, 
    const char* dname, unsigned char* buffer) {
    struct sockaddr_in* inet_addr;
    struct ifreq dconf;
    
    memset(&dconf, 0, sizeof(dconf));
    strncpy(dconf.ifr_name, dname, IFNAMSIZ);
    
    if (ioctl(fd, addr_type, &dconf) != 0)
        return -1;
    if (dconf.ifr_hwaddr.sa_family != AF_INET)
        return -2;
    
    inet_addr = (struct sockaddr_in*)&dconf.ifr_addr;
    memcpy(buffer, &inet_addr->sin_addr, IPV4_ADDR_SIZE);
    
    return 0;
}

static int get_ipv4_address(int fd, const char* dname, unsigned char* buffer) {
    return get_ipv4_record(fd, SIOCGIFADDR, dname, buffer);
}

static int get_ipv4_netmask(int fd, const char* dname, unsigned char* buffer) {
    return get_ipv4_record(fd, SIOCGIFNETMASK, dname, buffer);
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

static struct net_device * get_device_info(int fd, const char* name) {
    struct net_device* result;
    
    result = malloc(sizeof(net_device));
    if (!result)
        return NULL;
    
    memset(result, 0, sizeof(net_device));
    
    if (!(result->name = string_dup(name))) {
        free(result);
        return NULL;
    }

    if (get_mac_address(fd, name, result->mac_address) != 0)
        goto err;
    if (get_ipv4_address(fd, name, result->ipv4_address) != 0)
        goto err;
    if (get_ipv4_netmask(fd, name, result->ipv4_netmask) != 0)
        goto err;
    
    return result;

err:
    net_free_device_list(result);
    
    return NULL;
}

struct net_device * net_find_devices() {
    struct net_device* result = NULL;
    struct net_device* tmp;
    struct ifreq dconf;
    int fd, ret, i = 0;
    
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return NULL;
    
    memset(&dconf, 0, sizeof(dconf));
    dconf.ifr_ifindex = ++i;
    
    while ((ret = ioctl(fd, SIOCGIFNAME, &dconf)) == 0) {
        tmp = get_device_info(fd, dconf.ifr_name);
        if (tmp) {
            tmp->next = result;
            result = tmp;
        }
        
        memset(&dconf, 0, sizeof(dconf));
        dconf.ifr_ifindex = ++i;
    }
    
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

const size_t net_get_mac_addr_size() {
    return MAC_ADDR_SIZE;
}

const size_t net_get_ipv4_addr_size() {
    return IPV4_ADDR_SIZE;
}

