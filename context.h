#pragma once

#include "sc_map.h"

typedef struct context {
  struct sc_map_str variables;
} ctx_t;

int ctx_init(ctx_t *ctx);
int ctx_add_variable(ctx_t *ctx, char *name, char *value);
char *ctx_resolve_variable(ctx_t *ctx, const char *variable);
char *ctx_resolve_value(ctx_t *ctx, const char *value);
