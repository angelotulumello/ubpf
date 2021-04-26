//
// Created by angelo on 26/04/21.
//

#include <stdbool.h>
#include "flow_cache.h"
#include "ubpf_int.h"

static inline struct cache_entry *
add_cache_entry_to_hash(struct cache_entry** flows,
                    u_char *key, size_t key_len)
{
    struct cache_entry *cache_entry = malloc(sizeof(struct cache_entry));

    cache_entry->key = malloc(sizeof(key_len));
    cache_entry->key_len = key_len;

    memcpy(cache_entry->key, key, key_len);

    cache_entry->ctx = malloc(sizeof(struct map_context));

    cache_entry->prev = NULL;
    cache_entry->next = NULL;

    HASH_ADD_KEYPTR(hh, *flows, cache_entry->key, cache_entry->key_len, cache_entry);

    return cache_entry;
}

static inline struct cache_entry *
find_cache_entry_in_hash(struct cache_entry *flows, u_char *key, size_t key_len)
{
    struct cache_entry *found = NULL;

    HASH_FIND(hh, flows, key, key_len, found);

    if (found)
        return found;
    else
        return NULL;
}

bool
cache_empty(struct cache_queue *cache)
{
    if (cache->count == 0)
        return true;
    else
        return false;
}

bool
cache_full(struct cache_queue *cache)
{
    if (cache->count == cache->nb_frames)
        return true;
    else
        return false;
}

void
dequeue(struct cache_queue *cache)
{
    if (cache_empty(cache))
        return;

    if (cache->front == cache->rear)
        cache->front = NULL;

    struct cache_entry *tmp = cache->rear;
    cache->rear = cache->rear->prev;

    if (cache->rear)
        cache->rear->next = NULL;

    tmp->next = NULL;
    tmp->prev = NULL;

    cache->count--;
}

void
enqueue(struct cache_queue *cache, struct cache_entry *req_entry)
{
    if (cache_full(cache)) {
        dequeue(cache);
    }

    req_entry->next = cache->front;

    if (cache_empty(cache)) {
        cache->rear = cache->front = req_entry;
    } else {
        cache->front->prev = req_entry;
        cache->front = req_entry;
    }

    cache->count++;
}

enum cache_result
reference_cache(struct cache_queue *cache,
                    struct cache_entry **flows,
                    u_char *key, size_t key_len,
                    struct cache_entry **out)
{
    struct cache_entry *req_entry = NULL;

    req_entry = find_cache_entry_in_hash(*flows, key, key_len);

    *out = req_entry;

    // If requested entry is not in hash
    if (!req_entry) {
        req_entry = add_cache_entry_to_hash(flows, key, key_len);

        *out = req_entry;

        enqueue(cache, req_entry);

        return NOT_IN_HASH;
    }
    // If req_entry is not in the cache
    else if (req_entry->prev == NULL && req_entry->next == NULL && cache->front != req_entry) {
        dequeue(cache);

        enqueue(cache, req_entry);

        return NOT_IN_CACHE;
    }
    // if requested entry is in cache but not at front
    else if (req_entry != cache->front) {
        // Unlink requested entry
        req_entry->prev->next = req_entry->next;
        if (req_entry->next)
            req_entry->next->prev = req_entry->prev;

        if (req_entry == cache->rear) {
            cache->rear = req_entry->prev;
            cache->rear->next = NULL;
        }

        req_entry->next = cache->front;
        req_entry->prev = NULL;

        req_entry->next->prev = req_entry;

        cache->front = req_entry;

        return NOT_IN_CACHE_FRONT;
    } else {  // Requested entry is in cache at first position
        return IN_CACHE_FRONT;
    }
}

struct cache_queue *
create_cache(unsigned int size)
{
    struct cache_queue *cache = malloc(sizeof(struct cache_queue));

    cache->count = 0;
    cache->front = cache->rear = NULL;

    cache->nb_frames = size;

    return cache;
}