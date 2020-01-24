#include <stdlib.h>

#include "devices.h"

struct net_device* net_new_device() {
    struct net_device* res = malloc(sizeof(struct net_device));
    
    if (!res) {
        return NULL;
    }

    memset(res, 0, sizeof(struct net_device));

    return res;
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
