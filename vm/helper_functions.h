//
// Created by angelo on 30/04/21.
//

#ifndef UBPF_HELPER_FUNCTIONS_H
#define UBPF_HELPER_FUNCTIONS_H

#include "ubpf.h"
#include "ubpf_int.h"

void *
ubpf_map_lookup(const struct ubpf_map *map, void *key);

int
ubpf_map_update(struct ubpf_map *map, const void *key, void *item);

int
ubpf_map_add(struct ubpf_map *map, void *item);

int
ubpf_map_delete(struct ubpf_map *map, const void *key);

uint64_t
ubpf_time_get_ns(void);

uint32_t
ubpf_hash(void *item, uint64_t size);

uint64_t
ubpf_get_smp_processor_id();

//TODO: not implemented
uint64_t
ubpf_csum_diff();

uint64_t
ubpf_xdp_adjust_head(void *xdp, uint64_t size);

uint64_t
ubpf_xdp_adjust_tail(void *xdp, uint64_t size);

uint64_t
ubpf_redirect_map();

void
register_functions(struct ubpf_vm *vm);

#endif //UBPF_HELPER_FUNCTIONS_H
