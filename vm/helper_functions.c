//
// Created by angelo on 30/04/21.
//

#include <time.h>
#include "helper_functions.h"
#include "ubpf_hashmap.h"

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

int
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

int
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

uint64_t
ubpf_time_get_ns(void)
{
    struct timespec curr_time = {0, 0};
    uint64_t curr_time_ns = 0;
    clock_gettime(CLOCK_REALTIME, &curr_time);
    curr_time_ns = curr_time.tv_nsec + curr_time.tv_sec * 1.0e9;
    return curr_time_ns;
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

uint32_t
ubpf_hash(void *item, uint64_t size)
{
    return hashlittle(item, (uint32_t)size, 0);
}

struct ubpf_func_proto ubpf_get_smp_processor_id_proto = {
        .func = (ext_func)ubpf_get_smp_processor_id,
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

uint64_t
ubpf_get_smp_processor_id() {
    return 0;
}

struct ubpf_func_proto ubpf_csum_diff_proto = {
        .func = (ext_func)ubpf_csum_diff,
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

//TODO: not implemented
uint64_t
ubpf_csum_diff() {
    return 0;
}

struct ubpf_func_proto ubpf_xdp_adjust_head_proto = {
        .func = (ext_func)ubpf_xdp_adjust_head,
        .arg_types = {
                XDP_MD_PTR,
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

uint64_t
ubpf_xdp_adjust_head(void *xdp, uint64_t size) {
    int _size = (int) (size);
    struct xdp_md *_xdp = (struct xdp_md *)xdp;

    if (_size < -PKT_HEADROOM || _size > PKT_HEADROOM) {
        return -1;
    } else {
        _xdp->data += _size;
        return 0;
    }
}

struct ubpf_func_proto ubpf_xdp_adjust_tail_proto = {
        .func = (ext_func)ubpf_xdp_adjust_tail,
        .arg_types = {
                XDP_MD_PTR,
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

uint64_t
ubpf_xdp_adjust_tail(void *xdp, uint64_t size) {
    int _size = (int) (size);
    struct xdp_md *_xdp = (struct xdp_md *)xdp;

    if (_size < -PKT_TAILROOM || _size > PKT_TAILROOM) {
        return -1;
    } else {
        _xdp->data_end += _size;
        return 0;
    }
}

void
register_functions(struct ubpf_vm *vm)
{
    ubpf_register_function(vm, MAP_LOOKUP, "ubpf_map_lookup", ubpf_map_lookup_proto);
    ubpf_register_function(vm, MAP_UPDATE, "ubpf_map_update", ubpf_map_update_proto);
    ubpf_register_function(vm, MAP_DELETE, "ubpf_map_delete", ubpf_map_delete_proto);
    ubpf_register_function(vm, MAP_ADD, "ubpf_map_add", ubpf_map_add_proto);
    ubpf_register_function(vm, TIME_GET_NS, "ubpf_time_get_ns", ubpf_time_get_ns_proto);
    ubpf_register_function(vm, HASH, "ubpf_hash", ubpf_hash_proto);
    ubpf_register_function(vm, GET_SMP_PROCESSOR_ID, "ubpf_get_smp_processor_id", ubpf_get_smp_processor_id_proto);
    ubpf_register_function(vm, CSUM_DIFF, "ubpf_csum_diff", ubpf_csum_diff_proto);
    ubpf_register_function(vm, XDP_ADJUST_HEAD, "ubpf_adjust_head", ubpf_xdp_adjust_head_proto);
    ubpf_register_function(vm, XDP_ADJUST_TAIL, "ubpf_adjust_tail", ubpf_xdp_adjust_tail_proto);
}
