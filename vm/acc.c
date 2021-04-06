/*
 * Copyright 2015 Big Switch Networks, Inc
 * Copyright 2017 Google Inc.
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

#define _GNU_SOURCE
#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <elf.h>
#include <math.h>
#include "ubpf.h"
#include "ubpf_hashmap.h"

void ubpf_set_register_offset(int x);
static void *readfile(const char *path, size_t maxlen, size_t *len);
static void register_functions(struct ubpf_vm *vm);

static void usage(const char *name)
{
    fprintf(stderr, "usage: %s [-h] [-j|--jit] [-m|--mem PATH] BINARY\n", name);
    fprintf(stderr, "\nExecutes the eBPF code in BINARY and prints the result to stdout.\n");
    fprintf(stderr, "If --mem is given then the specified file will be read and a pointer\nto its data passed in r1.\n");
    fprintf(stderr, "If --jit is given then the JIT compiler will be used.\n");
    fprintf(stderr, "\nOther options:\n");
    fprintf(stderr, "  -r, --register-offset NUM: Change the mapping from eBPF to x86 registers\n");
}

int main(int argc, char **argv)
{
    struct option longopts[] = {
        { .name = "help", .val = 'h', },
        { .name = "mem", .val = 'm', .has_arg=1 },
        { .name = "jit", .val = 'j' },
        { .name = "register-offset", .val = 'r', .has_arg=1 },
        { }
    };

    const char *mem_filename = NULL;
    bool jit = false;

    int opt;
    while ((opt = getopt_long(argc, argv, "hm:jr:", longopts, NULL)) != -1) {
        switch (opt) {
        case 'm':
            mem_filename = optarg;
            break;
        case 'j':
            jit = true;
            break;
        case 'r':
            ubpf_set_register_offset(atoi(optarg));
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (argc != optind + 1) {
        usage(argv[0]);
        return 1;
    }

    const char *code_filename = argv[optind];
    size_t code_len;
    void *code = readfile(code_filename, 1024*1024, &code_len);
    if (code == NULL) {
        return 1;
    }

    size_t mem_len = 0;
    void *mem = NULL;
    if (mem_filename != NULL) {
        mem = readfile(mem_filename, 1024*1024, &mem_len);
        if (mem == NULL) {
            return 1;
        }
    }

    struct ubpf_vm *vm = ubpf_create();
    if (!vm) {
        fprintf(stderr, "Failed to create VM\n");
        return 1;
    }

    register_functions(vm);

    /* 
     * The ELF magic corresponds to an RSH instruction with an offset,
     * which is invalid.
     */
    bool elf = code_len >= SELFMAG && !memcmp(code, ELFMAG, SELFMAG);

    char *errmsg;
    int rv;
    if (elf) {
	rv = ubpf_load_elf(vm, code, code_len, &errmsg);
    } else {
	rv = ubpf_load(vm, code, code_len, &errmsg);
    }

    free(code);

    if (rv < 0) {
        fprintf(stderr, "Failed to load code: %s\n", errmsg);
        free(errmsg);
        ubpf_destroy(vm);
        return 1;
    }

    uint64_t ret;

    if (jit) {
        ubpf_jit_fn fn = ubpf_compile(vm, &errmsg);
        if (fn == NULL) {
            fprintf(stderr, "Failed to compile: %s\n", errmsg);
            free(errmsg);
            return 1;
        }
        ret = fn(mem, mem_len);
    } else {
        ret = ubpf_exec(vm, mem, mem_len);
    }

    printf("0x%"PRIx64"\n", ret);

    ubpf_destroy(vm);

    return 0;
}

static void *readfile(const char *path, size_t maxlen, size_t *len)
{
    FILE *file;
    if (!strcmp(path, "-")) {
        file = fdopen(STDIN_FILENO, "r");
    } else {
        file = fopen(path, "r");
    }

    if (file == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
        return NULL;
    }

    void *data = calloc(maxlen, 1);
    size_t offset = 0;
    size_t rv;
    while ((rv = fread(data+offset, 1, maxlen-offset, file)) > 0) {
        offset += rv;
    }

    if (ferror(file)) {
        fprintf(stderr, "Failed to read %s: %s\n", path, strerror(errno));
        fclose(file);
        free(data);
        return NULL;
    }

    if (!feof(file)) {
        fprintf(stderr, "Failed to read %s because it is too large (max %u bytes)\n",
                path, (unsigned)maxlen);
        fclose(file);
        free(data);
        return NULL;
    }

    fclose(file);
    if (len) {
        *len = offset;
    }
    return data;
}
void *
ubpf_map_lookup(const struct ubpf_map *map, void *key)
{
  if (!map) {
    return NULL;
  }
  if (!map->ops.map_lookup) {
    return NULL;
  }
  if (!key) {
    return NULL;
  }
  return map->ops.map_lookup(map, key);
}

struct ubpf_func_proto ubpf_map_lookup_proto = {
        .func = (ext_func)ubpf_map_lookup,
        .arg_types = {
                MAP_PTR,
                PKT_PTR | MAP_VALUE_PTR | STACK_PTR | UNKNOWN,
                0xff,
                0xff,
                0xff,
        },
        .arg_sizes = {
                0xff,
                SIZE_MAP_KEY,
                0xff,
                0xff,
                0xff,
        },
        .ret = MAP_VALUE_PTR | NULL_VALUE,
};

int
ubpf_map_update(struct ubpf_map *map, const void *key, void *item)
{
  if (!map) {
    return -1;
  }
  if (!map->ops.map_update) {
    return -2;
  }
  if (!key) {
    return -3;
  }
  if (!item) {
    return -4;
  }
  return map->ops.map_update(map, key, item);
}

struct ubpf_func_proto ubpf_map_update_proto = {
        .func = (ext_func)ubpf_map_update,
        .arg_types = {
                MAP_PTR,
                PKT_PTR | MAP_VALUE_PTR | STACK_PTR,
                PKT_PTR | MAP_VALUE_PTR | STACK_PTR,
                0xff,
                0xff,
        },
        .arg_sizes = {
                0xff,
                SIZE_MAP_KEY,
                SIZE_MAP_VALUE,
                0xff,
                0xff,
        },
        .ret = UNKNOWN,
};

static int
ubpf_map_add(struct ubpf_map *map, void *item)
{
  if (!map) {
    return -1;
  }
  if (!map->ops.map_add) {
    return -2;
  }
  if (!item) {
    return -3;
  }
  return map->ops.map_add(map, item);
}

struct ubpf_func_proto ubpf_map_add_proto = {
        .func = (ext_func)ubpf_map_add,
        .arg_types = {
                MAP_PTR,
                PKT_PTR | MAP_VALUE_PTR | STACK_PTR,
                0xff,
                0xff,
                0xff,
        },
        .arg_sizes = {
                0xff,
                SIZE_MAP_VALUE,
                0xff,
                0xff,
                0xff,
        },
        .ret = UNKNOWN,
};

static int
ubpf_map_delete(struct ubpf_map *map, const void *key)
{
  if (!map) {
    return -1;
  }
  if (!map->ops.map_delete) {
    return -2;
  }
  if (!key) {
    return -3;
  }
  return map->ops.map_delete(map, key);
}

struct ubpf_func_proto ubpf_map_delete_proto = {
        .func = (ext_func)ubpf_map_delete,
        .arg_types = {
                MAP_PTR,
                PKT_PTR | MAP_VALUE_PTR | STACK_PTR,
                0xff,
                0xff,
                0xff,
        },
        .arg_sizes = {
                0xff,
                SIZE_MAP_KEY,
                0xff,
                0xff,
                0xff,
        },
        .ret = UNKNOWN,
};

static uint64_t
ubpf_time_get_ns(void)
{
  struct timespec curr_time = {0, 0};
  uint64_t curr_time_ns = 0;
  clock_gettime(CLOCK_REALTIME, &curr_time);
  curr_time_ns = curr_time.tv_nsec + curr_time.tv_sec * 1.0e9;
  return curr_time_ns;
}

struct ubpf_func_proto ubpf_time_get_ns_proto = {
        .func = (ext_func)ubpf_time_get_ns,
        .arg_types = {
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
        },
        .arg_sizes = {
                0xff,
                0xff,
                0xff,
                0xff,
                0xff,
        },
        .ret = UNKNOWN,
};

static uint32_t
ubpf_hash(void *item, uint64_t size)
{
  return hashlittle(item, (uint32_t)size, 0);
}

struct ubpf_func_proto ubpf_hash_proto = {
        .func = (ext_func)ubpf_hash,
        .arg_types = {
                PKT_PTR | MAP_VALUE_PTR | STACK_PTR,
                IMM,
                0xff,
                0xff,
                0xff,
        },
        .arg_sizes = {
                SIZE_PTR_MAX,
                SIZE_64,
                0xff,
                0xff,
                0xff,
        },
        .ret = UNKNOWN,
};

static void
register_functions(struct ubpf_vm *vm)
{
  ubpf_register_function(vm, 1, "ubpf_map_lookup", ubpf_map_lookup_proto);
  ubpf_register_function(vm, 2, "ubpf_map_update", ubpf_map_update_proto);
  ubpf_register_function(vm, 3, "ubpf_map_delete", ubpf_map_delete_proto);
  ubpf_register_function(vm, 4, "ubpf_map_add", ubpf_map_add_proto);
  ubpf_register_function(vm, 5, "ubpf_time_get_ns", ubpf_time_get_ns_proto);
  ubpf_register_function(vm, 6, "ubpf_hash", ubpf_hash_proto);
}