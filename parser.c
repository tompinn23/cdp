#include "parser.h"
#include "context.h"

#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

typedef enum tok_type {
  TOK_IDENT,
  TOK_COLON,
  TOK_ASSIGN,
  TOK_EQUALS,
  TOK_COMMAND,
  TOK_DOLLAR,
  TOK_LEFT_PAREN, TOK_RIGHT_PAREN,
  TOK_ERROR,
  TOK_WS,
  TOK_STRING,
  TOK_NEWLINE,
  TOK_EOF,
} tok_type;

static char *tok_name[] ={
  "IDENT",
  "COLON",
  "ASSIGN",
  "EQUALS",
  "COMMAND",
  "DOLLAR",
  "LEFT_PAREN", "RIGHT_PAREN",
  "ERROR",
  "WS",
  "STRING",
  "NEWLINE",
  "EOF",
};

typedef struct lex {
  const char *start;
  const char *current;
  int line;
} lex_t;

typedef struct tok {
  tok_type type;
  const char *start;
  int length;
  int line;
} tok_t;

static void init_lexer(lex_t *lex, const char *source) {
  lex->line = 1;
  lex->start = lex->current = source;
}

static tok_t make_token(lex_t *l, tok_type type) {
  tok_t tok = {
    .type = type,
    .start = l->start,
    .length = (int)(l->current - l->start),
    .line = l->line,
  };
  return tok;
}

static tok_t error_token(lex_t *l, const char *message) {
  return (tok_t){
    .type = TOK_ERROR,
    .start = message,
    .length = (int)strlen(message),
    .line = l->line
  };
}

static bool at_eof(lex_t *l) {
  return *l->current == '\0';
}

static char advance(lex_t *l) {
  l->current++;
  return l->current[-1];
}

static char peek(lex_t *l) {
  return *l->current;
}

static char peekn(lex_t *l) {
  if(at_eof(l)) return '\0';
  return l->current[1];
}

static tok_t make_ws(lex_t *l) {
  for(;;) {
    char c = peek(l);
    switch(c) {
      case ' ':
      case '\t':
        while((peek(l) == ' ' || peek(l) == '\t') && !at_eof(l)) advance(l);
        return make_token(l, TOK_WS);
      case '\r':
        advance(l);
        break;
      default:
        return (tok_t){ .type = TOK_WS, .length = 0, .line = l->line, .start = ""};
    }
  }
}

static tok_t make_string(lex_t *l) {
  while(peek(l) != '"' && !at_eof(l)) {
    if(peek(l) == '\n') l->line++;
    advance(l);
  }
  if(at_eof(l)) return error_token(l, "unterminated string");
  advance(l); //consume final quote

  return make_token(l, TOK_STRING);
}

static bool is_alpha(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
    c == '_';
}

static char* reserved = "<>:\"|?*()";

static bool is_reserved(char c) {
  if(c < 31 && c >= 0) {
    return true;
  }
  char *x = reserved;
  while(*x) {
    if(c == *x++) {
      return true;
    }
  }
  return false;
}

static tok_t make_identifier(lex_t *l) {
  while(!is_reserved(peek(l)) && !at_eof(l)) {
    advance(l);
  }
  return make_token(l, TOK_IDENT);
}

static tok_type identifier_type(lex_t *l) {
  return TOK_IDENT;
}

static tok_t scan_token(lex_t *l) {
  l->start = l->current;
  tok_t ws = make_ws(l);
  if(ws.length > 0) {
    return ws;
  }
  if(at_eof(l)) return make_token(l, TOK_EOF);

  char c = advance(l);
  if(is_alpha(c)) return make_identifier(l);
  switch(c) {
    case ':':
      if(peek(l) == '=') {
        advance(l);
        return make_token(l, TOK_ASSIGN);
      }
      return make_token(l, TOK_COLON);
    case '=':
      return make_token(l, TOK_EQUALS);
    case '$':
      return make_token(l, TOK_DOLLAR);
    case '(':
      return make_token(l, TOK_LEFT_PAREN);
    case ')':
      return make_token(l, TOK_RIGHT_PAREN);
    case '"':
      return make_string(l);
    case '\n':
      l->line++;
      return make_token(l, TOK_NEWLINE);
  }
 	return error_token(l, "unexpected character");
}

typedef struct parser {
  tok_t current, previous;
  lex_t *lex;
  bool had_error, panic_mode;
  ctx_t *context;
} parser_t;

static int init_parser(parser_t *p, lex_t *l, ctx_t *c) {
  memset(p, 0, sizeof *p);
  p->lex = l;
  p->context = c;
  p->had_error = p->panic_mode = false;
}

static void err_at(parser_t* p, tok_t* t, const char* message) {
	if(p->panic_mode) return;
	p->panic_mode = true;
	fprintf(stderr, "[line %d] err ", t->line);
	if(t->type == TOK_EOF) {
		fprintf(stderr, "at end");
	} else if(t->type == TOK_ERROR) {}
	else {
		fprintf(stderr, "at '%.*s'", t->length, t->start);
	}
	fprintf(stderr, ": %s\n", message);
	p->had_error = true;
}

static void err_at_current(parser_t* p, const char* message) {
	err_at(p, &p->current, message);
}

static void err(parser_t* p, const char* message) {
	err_at(p, &p->previous, message);
}

static void parse_advance(parser_t* p) {
	p->previous = p->current;
	for(;;) {
		p->current = scan_token(p->lex);
    printf("tok: [%s] - %.*s\n", tok_name[p->current.type], p->current.length, p->current.start);
		if(p->current.type != TOK_ERROR) break;
		err_at_current(p, p->current.start);
	}
}

static void expect(parser_t *p, tok_type type, const char* message) {
	if(p->current.type == type) {
		parse_advance(p);
		return;
	}

	err_at_current(p, message);
}

static void expectws(parser_t *p, tok_type type, const char *message) {
  while(p->current.type == TOK_WS) {
    parse_advance(p);
  }
  expect(p, type, message);
}

static bool current(parser_t* p, tok_type type) {
	return p->current.type == type;
}

static bool match(parser_t* p, tok_type type) {
	if(p->current.type != type) {
		return false;
	}
	return true;
}

static bool consume(parser_t *p, tok_type type) {
  if(p->current.type == type) {
    parse_advance(p);
    return true;
  }
  return false;
}
static bool consume_skipws(parser_t *p, tok_type type) {
  while(p->current.type == TOK_WS) { parse_advance(p); }
  return consume(p, type);
}

static void synchronize(parser_t *p) {
  p->panic_mode = false;
  while(p->current.type != TOK_EOF) {
    if(p->previous.type == TOK_NEWLINE) return;
    parse_advance(p);
  }
}

static void var_declaration(parser_t *p) {
  const char *name = strndup(p->previous.start, p->previous.length);
  if(consume(p, TOK_ASSIGN) && consume_skipws(p, TOK_STRING)) {
    printf("immediate assign\n");
    char *string = strndup(p->current.start, p->current.length);
    char* resolved = ctx_resolve_value(p->context, string);
    free(string);
    ctx_add_variable(p->context, name, resolved);
  } else if(consume(p, TOK_EQUALS) && consume_skipws(p, TOK_STRING)) {
    printf("lazy assign\n");
    char *string = strndup(p->current.start, p->current.length);
    ctx_add_variable(p->context, name, string);
  }
  expectws(p, TOK_NEWLINE, "expected newline");
}

static void rule(parser_t *p) {
  char *name = strndup(p->previous.start, p->previous.length);
  parse_advance(p); // advance past the colon once we've stored the rule name
  while(!match(p, TOK_NEWLINE)) {
    if(consume_skipws(p, TOK_DOLLAR) && consume(p, TOK_LEFT_PAREN) && consume(p, TOK_IDENT)) {
      printf("%.*s\n", p->previous.length, p->previous.start);
    }
  }
}

static void declaration(parser_t *p) {
  while(consume(p, TOK_NEWLINE)) {}
  if(consume(p, TOK_IDENT) && (current(p, TOK_EQUALS) || current(p, TOK_ASSIGN))) {
    var_declaration(p);
  }
  /* if consume an identifier and now we have colon */
  if(consume(p, TOK_IDENT) && current(p, TOK_COLON)) {
    rule(p);
  }
  if(p->panic_mode) synchronize(p);
}


static char* slurp(const char* path) {
  FILE* file = fopen(path, "rb");
  if(file == NULL) {
    printf("couldn't open file");
    return NULL;
  }
  fseek(file, 0L, SEEK_END);
  size_t fileSize = ftell(file);
  rewind(file);

  char* buffer = (char*)malloc(fileSize + 1);
  size_t bytesRead = fread(buffer, sizeof(char), fileSize, file);
  buffer[bytesRead] = '\0';

  fclose(file);
  return buffer;
}


int parse_file(const char *path) {
  char *source = slurp(path);
  if(!source) {
    return -1;
  }
  lex_t l;
  parser_t p;
  ctx_t context;
  ctx_init(&context);
  init_lexer(&l, source);
  init_parser(&p, &l, &context);

  parse_advance(&p);
  while(!match(&p, TOK_EOF) && !p.had_error) {
    printf("decl\n");
    declaration(&p);
    gets();
  }
  expect(&p, TOK_EOF, "expected end of file");
  if(p.had_error) {
    fprintf(stderr, "ERROR parsing\n");
  }
}






#ifdef PS_MAIN
int main(int argc, char **argv) {
  char *buf = slurp("test.mk");
  lex_t lex;
  init_lexer(&lex, buf);
  tok_t tok = scan_token(&lex);
  while(tok.type != TOK_EOF && tok.type != TOK_ERROR) {
    printf("token: %s  - %.*s\n", tok_name[tok.type], tok.length, tok.start);
    tok = scan_token(&lex);
  }
  printf("token: %s - %.*s\n", tok_name[tok.type], tok.length, tok.start);
  
  return 0;
}
#endif

