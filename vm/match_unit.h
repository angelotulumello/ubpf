//
// Created by angelo on 21/04/21.
//

#ifndef UBPF_MATCH_UNIT_H
#define UBPF_MATCH_UNIT_H

#include <stdint.h>
#include <stdbool.h>

#define round_up_to_8(x) ((x+7) & (-8))
#define MAX_OPS 8

enum alu_ops {
  ALU_OPS_NULL,
  ALU_OPS_LE,
  ALU_OPS_BE,
  ALU_OPS_AND,
  ALU_OPS_OR,
  ALU_OPS_LSH,
  ALU_OPS_RSH,
};

struct pkt_field_def {
  uint16_t offset;  // in bytes
  uint8_t len;      // in bits
  enum alu_ops op[MAX_OPS];
  uint8_t nb_ops;
  uint64_t imm[MAX_OPS];
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
    uint8_t nb_key_fields;
    struct key_field *key_fields;
};

struct match_entry {
  struct pkt_field *fields;
  struct action_entry *act;
  uint8_t nb_pkt_fields;
};

struct match_table {
  struct match_entry *entries;
  uint8_t nb_entries;
  struct pkt_field_def *field_defs;
};

struct action_entry *
lookup_entry(struct match_table *mat, struct pkt_field *parsed_fields);

int
parse_mat_json(const char *jstring, size_t buf_len, struct match_table *mat);

struct pkt_field *
parse_pkt_header(const u_char *pkt, struct match_table *mat);

void
dump_fields(struct pkt_field *parsed_fields, uint8_t nb_fields);

u_char *
generate_key(struct action_entry *act, const u_char *pkt, size_t *key_len);


#endif //UBPF_MATCH_UNIT_H
