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

#ifndef ARROW_CLIENT_UTILS_H
#define ARROW_CLIENT_UTILS_H

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

#endif // ARROW_CLIENT_UTILS_H
