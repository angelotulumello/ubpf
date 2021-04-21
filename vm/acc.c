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
#include "jsmn.h"

#include "ubpf.h"
#include "ubpf_hashmap.h"
#include "ubpf_array.c"

void ubpf_set_register_offset(int x);
static void *readfile(const char *path, size_t maxlen, size_t *len);
static void register_functions(struct ubpf_vm *vm);

static const unsigned char udp_pkt[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3c, 0xec, 0xef, 0x0c, 0xde, 0x60, 0x08, 0x00,
        0x45, 0x00, 0x00, 0x32, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0xa9, 0x9e, 0x08, 0x08,
        0x08, 0x08, 0xc0, 0xa8, 0x00, 0x64, 0x19, 0x49, 0x04, 0x49, 0x00, 0x1e, 0xb4, 0x9b,
        0x73, 0x75, 0x62, 0x73, 0x70, 0x61, 0x63, 0x65, 0x73, 0x75, 0x62, 0x73, 0x70, 0x61,
        0x63, 0x65, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58
};

static void usage(const char *name)
{
    fprintf(stderr, "usage: %s [-h] [-j|--jit] [-m|--mem PATH] BINARY\n", name);
    fprintf(stderr, "\nExecutes the eBPF code in BINARY and prints the result to stdout.\n");
    fprintf(stderr, "If --mem is given then the specified file will be read and a pointer\nto its data passed in r1.\n");
    fprintf(stderr, "\nOther options:\n");
    fprintf(stderr, "  -r, --register-offset NUM: Change the mapping from eBPF to x86 registers\n");
}

static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
    if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
        strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
        return 0;
    }
    return -1;
}

int main(int argc, char **argv)
{
    struct option longopts[] = {
        { .name = "help", .val = 'h', },
        { .name = "mem", .val = 'm', .has_arg=1 },
        { .name = "register-offset", .val = 'r', .has_arg=1 },
        { .name = "maps", .val = 'M', .has_arg=1},
        { }
    };

    const char *mem_filename = NULL;
    const char *json_filename = NULL;

    int opt;
    while ((opt = getopt_long(argc, argv, "hmM:r:", longopts, NULL)) != -1) {
        switch (opt) {
        case 'm':
            mem_filename = optarg;
            break;
        case 'r':
            ubpf_set_register_offset(atoi(optarg));
            break;
        case 'M':
            json_filename = optarg;
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
    } else {
        mem = (void *) udp_pkt;
        mem_len = 64;
    }

    struct ubpf_vm *vm = ubpf_create();
    if (!vm) {
        fprintf(stderr, "Failed to create VM\n");
        return 1;
    }

    register_functions(vm);

    uint64_t ret;

    /*
     * Maps parsing from json
     */
    jsmn_parser jparser;
    jsmntok_t toks[128];
    int jret;
    FILE *jfile;
    long jsize;
    char *json_str;

    int nb_maps;

    jfile = fopen(json_filename, "r");
    fseek(jfile, 0, SEEK_END);
    jsize = ftell(jfile);
    rewind(jfile);

    json_str = malloc(jsize + 1);
    fread(json_str, 1, jsize, jfile);

    fclose(jfile);

    jsmn_init(&jparser);
    jret = jsmn_parse(&jparser, json_str, jsize,
                        toks, sizeof(toks)/sizeof(toks[0]));

    if (jret < 0) {
      fprintf(stderr, "Failed to parse JSON: %d\n", jret);
      return 1;
    }

    if (jret < 1 || toks[0].type != JSMN_ARRAY) {
      printf("Array expected\n");
      return 1;
    }

    nb_maps = toks[0].size;

    int start = 2;
    int next = toks[1].end;

    for (int j=0; j<nb_maps; j++) {
        long offset, type, key_size, value_size, max_entries;
        struct ubpf_map *map;
        const char *hname = "hashmap";
        const char *aname = "arraymap";
        const char *sym_name;
        int i;

        for (i = start; i < next; i++) {
            if (jsoneq(json_str, &toks[i], "offset") == 0) {
                offset = strtol(json_str + toks[i+1].start,
                                &json_str + toks[i+1].end, 10);
                printf("offset: %ld\n", offset);

                i++;
            } else if (jsoneq(json_str, &toks[i], "type") == 0) {
                type = strtol(json_str + toks[i+1].start,
                              (char **) json_str + toks[i+1].end, 10);
                printf("type: %ld\n", type);
                i++;
            } else if (jsoneq(json_str, &toks[i], "key_size") == 0) {
                key_size = strtol(json_str + toks[i+1].start,
                              (char **) json_str + toks[i+1].end, 10);
                printf("key_size: %ld\n", key_size);
                i++;
            } else if (jsoneq(json_str, &toks[i], "value_size") == 0) {
                value_size = strtol(json_str + toks[i+1].start,
                                  (char **) json_str + toks[i+1].end, 10);
                printf("value_size: %ld\n", value_size);
                i++;
            } else if (jsoneq(json_str, &toks[i], "max_entries") == 0) {
                max_entries = strtol(json_str + toks[i+1].start,
                                  (char **) json_str + toks[i+1].end, 10);
                printf("max_entries: %ld\n", max_entries);
                i++;
            } else if (toks[i].type == JSMN_OBJECT) {
                break;
            } else {
                fprintf(stderr,"Key not recognized\n");
                continue;
            }
        }
        map = malloc(sizeof(struct ubpf_map));

        map->type = type;
        map->key_size = key_size;
        map->value_size = value_size;
        map->max_entries = max_entries;

        switch (map->type) {
            case UBPF_MAP_TYPE_ARRAY:
                map->ops = ubpf_array_ops;
                map->data = ubpf_array_create(map);
                sym_name = aname;
                break;
            case UBPF_MAP_TYPE_HASHMAP:
                map->ops = ubpf_hashmap_ops;
                map->data = ubpf_hashmap_create(map);
                sym_name = hname;
                break;
            default:
                ubpf_error("unrecognized map type: %d", map->type);
                free(map);
                return 1;
        }

        int result = ubpf_register_map(vm, sym_name, map);
        if (result == -1) {
            ubpf_error("failed to register variable '%s'", sym_name);
            free(map);
            return 1;
        }

        *(uint32_t *)((uint64_t)code + offset*8 + 4) = (uint32_t)((uint64_t)map);
        *(uint32_t *)((uint64_t)code + offset*8 + sizeof(struct ebpf_inst) + 4) = (uint32_t)((uint64_t)map >> 32);

        printf("map: %lx\n", (uint64_t) map);

        start = i + 1;
        next = i + 1 + toks[i].size*2;
    }

    free(json_str);

    /*
     * Load program
     */
    char *errmsg;
    int rv;

    rv = ubpf_load(vm, code, code_len, &errmsg);

    free(code);

    if (rv < 0) {
        fprintf(stderr, "Failed to load code: %s\n", errmsg);
        free(errmsg);
        ubpf_destroy(vm);
        return 1;
    }

    void *key, *value;

    key = malloc(16);
    *(uint64_t *)key = 0xca8006408080808;
    *(uint32_t *)(key+8) = 0x49194904;
    *(uint8_t *)(key+12) = 0x11;

    value=malloc(4);
    *(uint32_t *)value = 2;

    ubpf_hashmap_update(vm->ext_maps[0], key, value);

    /*
     * Execute the program
     */
    ret = ubpf_exec(vm, mem, mem_len);

    printf("0x%"PRIx64"\n", ret);

    /*
     * Execute the program the second time
     */
    ret = ubpf_exec(vm, mem, mem_len);

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