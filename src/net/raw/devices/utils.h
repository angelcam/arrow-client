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

#ifndef ARROW_CLIENT_DEVICES_UTILS_H
#define ARROW_CLIENT_DEVICES_UTILS_H

#include "devices.h"

static char* string_dup(const char* str) {
    char* result;
    size_t len;

    if (!str) {
        return NULL;
    }

    len = strlen(str);

    result = malloc(len + 1);

    if (!result) {
        return NULL;
    }

    memcpy(result, str, len);
    result[len] = 0;

    return result;
}

static int get_ipv4_record(struct sockaddr* addr, unsigned char* buffer) {
    struct sockaddr_in* inet_addr;

    if (addr->sa_family != AF_INET)
        return -1;

    inet_addr = (struct sockaddr_in*)addr;

    memcpy(buffer, &inet_addr->sin_addr, IPV4_ADDR_SIZE);

    return 0;
}

#endif // ARROW_CLIENT_DEVICES_UTILS_H
