//
// Created by angelo on 21/04/21.
//

#ifndef UBPF_MATCH_UNIT_H
#define UBPF_MATCH_UNIT_H

#include <stdint.h>
#include <stdbool.h>

enum alu_ops {
  ALU_OPS_NULL,
  ALU_OPS_LE,
  ALU_OPS_BE,
  ALU_OPS_AND
};

struct pkt_field_def {
  uint16_t offset;  // in bytes
  uint8_t len;      // in bits
  enum alu_ops op;
  uint64_t imm;
};

struct pkt_field {
  void *value;
  bool dontcare;
};

enum action_ops {
  XDP_ABORTED = 0,
  XDP_DROP,
  XDP_PASS,
  XDP_TX,
  XDP_REDIRECT,
  MAP_ACCESS
};

struct key_field {
  uint8_t kstart;
  uint8_t kend;
  uint64_t imm;
  bool has_imm;
  struct pkt_field_def pkt_fld;
};

struct action_entry {
    enum action_ops op;
    uint8_t map_id;
    uint8_t key_len;
    struct key_field *key_fields;
};

struct match_entry {
  struct pkt_field *fields;
  struct action_entry *act;
  uint8_t nb_pkt_fields;
  uint8_t nb_key_fields;
};

struct match_table {
  struct match_entry *entries;
  uint8_t nb_entries;
  struct pkt_field_def *field_defs;
};

struct match_table *
create_match_table (struct match_entry *entries,
                            uint8_t nb_entries);

struct match_entry *
create_match_entry (struct pkt_field *fields,
                        struct action_entry *act,
                        uint8_t nb_pkt_fields,
                        uint8_t nb_key_fields);

void *
parse_field(void *pkt_data, struct pkt_field_def *fdef,
                    struct pkt_field *field);

int
lookup_entry(struct match_entry *entry);

enum action_ops
execute_action(struct match_entry *entry, void *pkt_data, void *key);

int
parse_mat_json(const char *jstring, size_t buf_len, struct match_table *mat);


#endif //UBPF_MATCH_UNIT_H
