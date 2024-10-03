#include "context.h"
#include "parser.h"

#include "sc_map.h"
#include "strbuf.h"
#include <ctype.h>

#include <stdio.h>
#include <stdlib.h>

char *ctx_resolve_value(ctx_t *ctx, const char *str) {
  if(str == NULL) {
    return NULL;
  }
  char *copy = strdup(str);
  if(!copy) {
    return NULL;
  }
  char *p = copy, *n = copy;
  sbuf_t *s = sbuf_init();
  if(!s) {
    return NULL;
  }
  while(*p != '\0') {
    if(*p == '$' && *(p + 1) == '(') {
      sbuf_nappend(s, n, (int)(p - n));
      n = p + 2;
      while(*p != ')') p++;
      *p = '\0';
      char *val = ctx_resolve_variable(ctx, n);
      *p = ')';
      if(val != NULL) {
        sbuf_append(s, val);
      }
      p++;
      n = p;
    }
    p++;
  }
  sbuf_append(s, n);
  return sbuf_finish(s);
}

int ctx_init(ctx_t *ctx) {
  sc_map_init_str(&ctx->variables, 0, 0);
  return 0;
}

char *ctx_resolve_variable(ctx_t *ctx, const char *variable) {
  const char *val = sc_map_get_str(&ctx->variables, variable);
  if(val == NULL) {
    val = getenv(variable);
  }
  return ctx_resolve_value(ctx, val);
}

int ctx_add_variable(ctx_t *ctx, char *name, char *value) {
  sc_map_put_str(&ctx->variables, name, value);
}


int main(int argc, char **argv) {
  ctx_t ctx;
  ctx_init(&ctx);
  sc_map_put_str(&ctx.variables, "EXEDIR", "/usr/bin");
  char * val = ctx_resolve_value(&ctx, "$(EXEDIR)/gcc-$(CC)-x86");
  printf("val=%s\n", val);

  parse_file("./test.mk");
}

