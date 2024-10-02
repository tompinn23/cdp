#pragma once

#include "sc_map.h"

typedef struct context {
  struct sc_map_str variables;
} ctx_t;

char *ctx_resolve_var(ctx_t *ctx, char *variable);
