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
#include <pcap.h>

#include "cJSON.h"

#include "ubpf.h"
#include "ubpf_hashmap.h"
#include "ubpf_array.c"
#include "match_unit.h"
#include "flow_cache.h"
#include "helper_functions.h"

void ubpf_set_register_offset(int x);
static void *readfile(const char *path, size_t maxlen, size_t *len);
static inline void
init_output_pcap (FILE **fp, const char *filename);
static inline void
write_pkt(const u_char *pkt_ptr, size_t len, FILE *fp);

static const unsigned char udp_pkt[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3c, 0xec, 0xef, 0x0c, 0xde, 0x60, 0x08, 0x00,
        0x45, 0x00, 0x00, 0x32, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0xa9, 0x9e, 0x08, 0x08,
        0x08, 0x08, 0xc0, 0xa8, 0x00, 0x64, 0x19, 0x49, 0x04, 0x49, 0x00, 0x1e, 0xb4, 0x9b,
        0x73, 0x75, 0x62, 0x73, 0x70, 0x61, 0x63, 0x65, 0x73, 0x75, 0x62, 0x73, 0x70, 0x61,
        0x63, 0x65, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58
};

typedef struct pcap_hdr_s {
  uint32_t magic_number;   /* magic number */
  uint16_t version_major;  /* major version number */
  uint16_t version_minor;  /* minor version number */
  int32_t  thiszone;       /* GMT to local correction */
  uint32_t sigfigs;        /* accuracy of timestamps */
  uint32_t snaplen;        /* max length of captured packets, in octets */
  uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
  uint32_t ts_sec;         /* timestamp seconds */
  uint32_t ts_usec;        /* timestamp microseconds */
  uint32_t incl_len;       /* number of octets of packet saved in file */
  uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

const pcap_hdr_t pcap_global_hdr = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 0xffff,
        .network = 0x0001
};

pcaprec_hdr_t pcaprec_hdr = {0};


static void usage(const char *name)
{
    fprintf(stderr, "usage: %s [-h] [-j|--jit] [-M|--maps MAP_FILE] [-p|--pcap PATH]"
                    " [-m|--mat MAT_FILE] BINARY\n", name);
    fprintf(stderr, "\nExecutes the eBPF code in BINARY and prints the result to stdout.\n");
    fprintf(stderr, "If --mem is given then the specified file will be read and a pointer\nto its data passed in r1.\n");
    fprintf(stderr, "\nIf --pcap is given then the specified trace will be read and the ubpf \nprogram is "
                    "executed for each packet in the trace\n");
    fprintf(stderr, "\nIf --maps is given then the specified file will be read and the encoded\nmaps will "
                    "be created in the ubpf VM\n");
    fprintf(stderr, "\nOther options:\n");
    fprintf(stderr, "  -r, --register-offset NUM: Change the mapping from eBPF to x86 registers\n");
}

static inline int
parse_prog_maps(const char *json_filename, struct ubpf_vm *vm, void *code)
{
    /*
     * Maps parsing from json
     */
    cJSON *json = NULL;
    FILE *jfile;
    long jsize;
    char *json_str;

    jfile = fopen(json_filename, "r");
    fseek(jfile, 0, SEEK_END);
    jsize = ftell(jfile);
    rewind(jfile);

    json_str = malloc(jsize + 1);
    fread(json_str, 1, jsize, jfile);

    fclose(jfile);

    json = cJSON_ParseWithLength(json_str, jsize);
    if (json == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
            fprintf(stderr, "Error before: %s\n", error_ptr);
        return -1;
    }

    if (!cJSON_IsArray(json)) {
        fprintf(stderr, "Root JSON object not an array\n");
        return -1;
    }

    cJSON *jmap, *jmaps = json;

    cJSON_ArrayForEach(jmap, jmaps) {
        size_t nb_offsets = 0;
        unsigned int offset[8], type, key_size, value_size, max_entries;
        struct ubpf_map *map;
        const char *hname = "hashmap";
        const char *aname = "arraymap";
        const char *sym_name;

        cJSON *jtype = cJSON_GetObjectItemCaseSensitive(jmap, "type");
        cJSON *jkey_size = cJSON_GetObjectItemCaseSensitive(jmap, "key_size");
        cJSON *jvalue_size = cJSON_GetObjectItemCaseSensitive(jmap, "value_size");
        cJSON *jmax_entries = cJSON_GetObjectItemCaseSensitive(jmap, "max_entries");

        type = (unsigned int) cJSON_GetNumberValue(jtype);
        key_size = (unsigned int) cJSON_GetNumberValue(jkey_size);
        value_size = (unsigned int) cJSON_GetNumberValue(jvalue_size);
        max_entries = (unsigned int) cJSON_GetNumberValue(jmax_entries);

        cJSON *joff, *joffsets = cJSON_GetObjectItemCaseSensitive(jmap, "offsets");

        cJSON_ArrayForEach(joff, joffsets) {
            offset[nb_offsets] = (unsigned int) cJSON_GetNumberValue(joff);
            nb_offsets++;
        }

        map = malloc(sizeof(struct ubpf_map));

        map->type = type;
        map->key_size = key_size;
        map->value_size = value_size;
        map->max_entries = max_entries;

        switch (map->type) {
            case UBPF_MAP_TYPE_PER_CPU_ARRAY:  // per cpu array
            case UBPF_MAP_TYPE_ARRAY:
                map->ops = ubpf_array_ops;
                map->data = ubpf_array_create(map);
                sym_name = aname;
                break;
            case UBPF_MAP_TYPE_PER_CPU_HASHMAP:  // per cpu hash
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

        for (int i=0; i<nb_offsets; i++) {
            *(uint32_t *) ((uint64_t) code + offset[i] * 8 + 4) = (uint32_t) ((uint64_t) map);
            *(uint32_t *) ((uint64_t) code + offset[i] * 8 + sizeof(struct ebpf_inst) + 4) =
                    (uint32_t) ((uint64_t) map >> 32);
        }

        printf("map: %lx\n", (uint64_t) map);
    }

    free(json_str);

    return 0;
}

int main(int argc, char **argv)
{
    struct option longopts[] = {
        { .name = "help", .val = 'h', },
        { .name = "mat", .val = 'm', .has_arg=1 },
        { .name = "register-offset", .val = 'r', .has_arg=1 },
        { .name = "maps", .val = 'M', .has_arg=1},
        { .name = "pcap", .val = 'p', .has_arg=1},
        { }
    };

    const char *mat_filename = NULL;
    const char *json_filename = NULL;
    const char *pcap_filename = NULL;

    int opt;
    while ((opt = getopt_long(argc, argv, "hm:p:M:r:", longopts, NULL)) != -1) {
        switch (opt) {
        case 'm':
            mat_filename = optarg;
            break;
        case 'r':
            ubpf_set_register_offset(atoi(optarg));
            break;
        case 'M':
            json_filename = optarg;
            break;
        case 'p':
            pcap_filename = optarg;
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

    (void) *udp_pkt;

    struct ubpf_vm *vm = ubpf_create();
    if (!vm) {
        fprintf(stderr, "Failed to create VM\n");
        return 1;
    }

    register_functions(vm);

    uint64_t ret;

    ret = parse_prog_maps(json_filename, vm, code);
    if (ret != 0) {
        fprintf(stderr,"Error in parsing maps and bpf code\n");
        ubpf_destroy(vm);
        return ret;
    }

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

    /*
     * Parse the json of the MAT if any
     */
    struct match_table *mat = NULL;

    if(mat_filename) {
        FILE *mat_file;
        size_t mat_size;
        char *mat_string;

        mat_file = fopen(mat_filename, "r");
        fseek(mat_file, 0, SEEK_END);
        mat_size = ftell(mat_file);
        rewind(mat_file);

        mat_string = malloc(mat_size + 1);
        fread(mat_string, 1, mat_size, mat_file);

        fclose(mat_file);

        mat = malloc(sizeof(struct match_table));

        if (parse_mat_json(mat_string, mat_size, mat) < 0){
            fprintf(stderr, "error in parsing MAT\n");
            free(mat);
            free(mat_string);
            return -1;
        }
        free(mat_string);
    }

    printf("map 0 key_size %d\n", vm->ext_maps[0]->key_size);
    printf("map 1 key_size %d\n", vm->ext_maps[1]->key_size);


    /*
     * Create an entry in the hashmap
     */
    void *tmp_key, *value;

    tmp_key = malloc(16);
    *(uint64_t *)tmp_key = 0x44332211ddccbbaa;
    *(uint32_t *)(tmp_key + 8) = 0xddccbbaa;
    *(uint32_t *)(tmp_key + 12) = 0x11;

    value=malloc(4);
    *(uint32_t *)value = 3;

    ubpf_hashmap_update(vm->ext_maps[1], tmp_key, value);

    // ip.dst | ip.src | udp.sport | udp.dport | ip.proto
    *(uint64_t *)tmp_key = 0x44332211ddccbbaa;
    *(uint32_t *)(tmp_key + 8) = 0xddccbbaa;
    *(uint32_t *)(tmp_key + 12) = 0x06;

    *(uint32_t *)value = 2;

    ubpf_hashmap_update(vm->ext_maps[1], tmp_key, value);

    u_char data[128];
    unsigned  int c = 0;
    c = ubpf_hashmap_dump(vm->ext_maps[1], data);
    (void )c;

    printf("Count: %d\n", c);

    free(tmp_key);
    free(value);

    /*
     * Pcap trace parsing and main processing loop
     */
    if (pcap_filename) {
        pcap_t *p;
        char errbuf[PCAP_ERRBUF_SIZE];
        const u_char *pkt_ptr;
        struct pcap_pkthdr *hdr;
        FILE *out_pass, *out_drop, *out_map, *out_tx, *out_redirect;
        int npkts = 1;
        struct cache_queue *cache = NULL;
        struct cache_entry *map_entries = NULL;

        p = pcap_open_offline(pcap_filename, errbuf);

        if (p == NULL) {
            fprintf(stderr, "pcap_open_offline failed: %s\n", errbuf);
            return -1;
        }

        out_pass = out_drop = out_map = out_tx = out_redirect = NULL;
        // Init the output pcap with the pcap header
        init_output_pcap(&out_pass, "pass.pcap");
        init_output_pcap(&out_drop, "drop.pcap");
        init_output_pcap(&out_map, "map_access.pcap");
        init_output_pcap(&out_tx, "tx.pcap");
        init_output_pcap(&out_redirect, "redirect.pcap");

        /*
         * Create the flow cache
         */
        cache = create_cache(CACHE_SIZE);

        /*
         * Execute the program for each packet
         */
        while (pcap_next_ex(p, &hdr, &pkt_ptr) > 0) {
            struct pkt_field *extracted_fields;
            struct action_entry *act;
            u_char *key = NULL;
            size_t key_len = 0;

            printf( "\n--------- Packet #%d\n\n", npkts);

            if (mat) {
                extracted_fields = parse_pkt_header(pkt_ptr, mat);

                act = lookup_entry(mat, extracted_fields);

                if (act) {
                    switch (act->op) {
                        case XDP_ABORTED:
                        case XDP_DROP:
                            ret = XDP_DROP;
                            write_pkt(pkt_ptr, hdr->len, out_drop);
                            break;
                        case XDP_PASS:
                            ret = XDP_PASS;
                            write_pkt(pkt_ptr, hdr->len, out_pass);
                            break;
                        case XDP_TX:
                            ret = XDP_TX;
                            write_pkt(pkt_ptr, hdr->len, out_tx);
                            break;
                        case XDP_REDIRECT:
                            ret = XDP_REDIRECT;
                            write_pkt(pkt_ptr, hdr->len, out_redirect);
                            break;
                        case MAP_ACCESS:
                            key = generate_key(act, pkt_ptr, &key_len);
                            if (key) {
                                enum cache_result res;
                                struct cache_entry *entry;
                                struct map_context *in_ctx, *out_ctx;
                                uint16_t map_id;

                                res = reference_cache(cache, &map_entries, key, key_len, &entry);

                                switch (res) {
                                    case NOT_IN_HASH:
                                        printf("NOT_IN_HASH\n");
                                        in_ctx = NULL;
                                        out_ctx = entry->ctx;
                                        break;
                                    case NOT_IN_CACHE:
                                        printf("NOT_IN_CACHE\n");

                                        in_ctx = entry->ctx;
                                        out_ctx = NULL;
                                        break;
                                    case NOT_IN_CACHE_FRONT:
                                        printf("NOT_IN_CACHE_FRONT\n");

                                        in_ctx = entry->ctx;
                                        out_ctx = NULL;
                                        break;
                                    case IN_CACHE_FRONT:
                                        printf("IN_CACHE_FRONT\n");

                                        in_ctx = entry->ctx;
                                        out_ctx = NULL;
                                        break;
                                    default:
                                        break;
                                }

                                map_id = (uint8_t) key[key_len - 1];
                                printf("map id = %d\n", map_id);

                                ret = ubpf_exec(vm, (void *) pkt_ptr, hdr->len, in_ctx, out_ctx, map_id);
                                write_pkt(pkt_ptr, hdr->len, out_map);
                            }
                            break;
                    }
                }
            } else {  // no MAT, standard processing
                ret = ubpf_exec(vm, (void *) pkt_ptr, hdr->len, NULL, NULL, 0);
            }

            printf("return 0x%"PRIx64"\n\n", ret);
            npkts++;
        }

        fclose(out_pass);
        fclose(out_drop);
        fclose(out_tx);
        fclose(out_map);
        fclose(out_redirect);
    }

    ubpf_destroy(vm);

    return 0;
}


static void
init_output_pcap (FILE **fp, const char *filename) {
    *fp = fopen(filename, "wb");
    fwrite(&pcap_global_hdr, 1, sizeof(pcap_hdr_t), *fp);

    if(!*fp) {
        printf("Error cannot open %s\n", filename);
        exit(-1);
    }
}

static void
write_pkt(const u_char *pkt_ptr, size_t len, FILE *fp) {
    // update length of the packet
    pcaprec_hdr.incl_len = len;
    pcaprec_hdr.orig_len = len;

    // write packet to output file
    fwrite(&pcaprec_hdr, 1, sizeof(pcaprec_hdr_t), fp);
    fwrite(pkt_ptr, 1, len, fp);
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