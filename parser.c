
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

typedef enum tok_type {
  TOK_IDENT,
  TOK_COLON,
  TOK_ASSIGN,
  TOK_COMMAND,
  TOK_DOLLAR,
  TOK_LEFT_PAREN, TOK_RIGHT_PAREN,
  TOK_ERROR,
  TOK_SPACES,
  TOK_TABS,
  TOK_STRING,
  TOK_NEWLINE,
  TOK_EOF,
} tok_type;

static char *tok_name[] ={
  "IDENT",
  "COLON",
  "ASSIGN",
  "COMMAND",
  "DOLLAR",
  "LEFT_PAREN", "RIGHT_PAREN",
  "ERROR",
  "SPACES",
  "TABS",
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
        while(peek(l) == ' ' && !at_eof(l)) advance(l);
        return make_token(l, TOK_SPACES);
      case '\t':
        while(peek(l) == '\t' && !at_eof(l)) advance(l);
        return make_token(l, TOK_TABS);
      case '\r':
        advance(l);
        break;
      default:
        return (tok_t){ .type = TOK_SPACES, .length = 0, .line = l->line, .start = ""};
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

static char* reserved = "<>:\"|?*";

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
