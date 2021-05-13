#ifndef UBPF_UBPF_LPM_H
#define UBPF_UBPF_LPM_H

#include "ubpf_int.h"
#include "uthash.h"

void *ubpf_lpm_create(const struct ubpf_map *map);
unsigned int ubpf_lpm_size(const struct ubpf_map *map);
unsigned int ubpf_lpm_dump(const struct ubpf_map *map, void *data);
void *ubpf_lpm_lookup(const struct ubpf_map *map, const void *key);
int ubpf_lpm_update(struct ubpf_map *map, const void *key, void *value);
int ubpf_lpm_delete(struct ubpf_map *map, const void *key);

struct lpm_hmap {
  UT_hash_handle hh;
  uint32_t key[4];
  void *value;
};

typedef struct ubpf_lpm {
  struct lpm_hmap **lpm_hmaps;  // array of hashmaps
  uint8_t lpm_size;
  unsigned int count;
} ubpf_lpm_t;

static const struct ubpf_map_ops ubpf_lpm_ops = {
        .map_size = ubpf_lpm_size,
        .map_dump = ubpf_lpm_dump,
        .map_lookup = ubpf_lpm_lookup,
        .map_update = ubpf_lpm_update,
        .map_delete = ubpf_lpm_delete,
        .map_add = NULL,
};

#endif //UBPF_UBPF_LPM_H
