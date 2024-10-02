#pragma once

#include <stddef.h>

typedef struct sbuf {
  char *buf;
  size_t len;
  size_t cap;
} sbuf_t;

sbuf_t *sbuf_init();
int sbuf_putc(sbuf_t *s, char c);
int sbuf_append(sbuf_t *s, char *str);
int sbuf_nappend(sbuf_t *s, char *str, size_t len); 

char *sbuf_finish(sbuf_t *s);
