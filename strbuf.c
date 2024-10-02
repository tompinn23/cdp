#include "strbuf.h"

#include <stdlib.h>
#include <string.h>

int sbuf_realloc(sbuf_t *s, size_t min) {
  size_t new = s->cap == 0 ? 8 : s->cap * 2;
  while(new < min) {
    new *= 2;
  }
  char *buf = realloc(s->buf, new);
  if(!buf) {
    return -1;
  }
  s->buf = buf;
  s->cap = new;
  return 0;
}

sbuf_t *sbuf_init() {
  sbuf_t *buf = calloc(1, sizeof(*buf));
  return buf;
}

int sbuf_putc(sbuf_t *s, char c) {
  if(sbuf_realloc(s, s->len + 1) < 0) {
    return -1;
  }
  s->buf[s->len++] = c;
  return 0;
}

int sbuf_append(sbuf_t *s, char *str) {
  return sbuf_nappend(s, str, strlen(str));
}

int sbuf_nappend(sbuf_t *s, char *str, size_t n) {
  if(sbuf_realloc(s, s->len + n) < 0) {
    return -1;
  }
  memcpy(s->buf + s->len, str, n);
  s->len += n;
  return 0;
}

char *sbuf_finish(sbuf_t *s) {
  char *final = realloc(s->buf, s->len + 1);
  final[s->len] = '\0';
  free(s);
  return final;
}

