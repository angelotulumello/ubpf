/*
 * Copyright 2018 Orange
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
#include "inttypes.h"

//#include <config.h>
//#include "util.h"

#include "ubpf_int.h"

void *ubpf_array_create(const struct ubpf_map *map);
static void *ubpf_array_lookup(const struct ubpf_map *map, const void *key);
static int ubpf_array_update(struct ubpf_map *map, const void *key,
                             void *value);

const struct ubpf_map_ops ubpf_array_ops = {
    .map_lookup = ubpf_array_lookup,
    .map_update = ubpf_array_update,
    .map_delete = NULL,
    .map_add = NULL,
};

void *
ubpf_array_create(const struct ubpf_map *map)
{
    return calloc(map->max_entries, map->value_size);
}

static void *
ubpf_array_lookup(const struct ubpf_map *map, const void *key)
{
    uint64_t mask = (1u << (map->key_size*8)) - 1;

    uint64_t idx = *((const uint64_t *)key) & mask;
    if (idx >= map->max_entries) {
        printf("Nulletto\n");
        return NULL;
    }
    return (void *)((uint64_t)map->data + idx * map->value_size);
}

static int
ubpf_array_update(struct ubpf_map *map, const void *key, void *value)
{
    uint64_t idx = *((const uint64_t *)key);
    if (idx >= map->max_entries) {
        return -5;
    }
    void *addr = (void *)((uint64_t)map->data + map->value_size * idx);
    memcpy(addr, value, map->value_size);
    return 0;
}
