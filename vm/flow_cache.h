//
// Created by angelo on 26/04/21.
//

#ifndef UBPF_FLOW_CACHE_H
#define UBPF_FLOW_CACHE_H

#include "uthash.h"
#include "ubpf.h"

#define CACHE_SIZE 8
#define HASH_SIZE 1<<20

struct cache_entry {
  u_char *key;
  size_t key_len;
  struct map_context *ctx;
  struct cache_entry *prev, *next;
  UT_hash_handle hh;
};

struct cache_queue {
  unsigned int count;
  unsigned int nb_frames;
  struct cache_entry *front, *rear;
};

enum cache_result {
  NOT_IN_HASH = 0,
  NOT_IN_CACHE,
  NOT_IN_CACHE_FRONT,
  IN_CACHE_FRONT
};

enum cache_result
reference_cache(struct cache_queue *cache,
                struct cache_entry **flows,
                u_char *key, size_t key_len,
                struct cache_entry **out);

struct cache_queue *
create_cache(unsigned int size);


#endif //UBPF_FLOW_CACHE_H
