
.PHONY: all
all: cdpfs cdp

cdpfs:
	gcc -Wall cdpfs.c `pkg-config fuse3 --cflags --libs` -o cdpfs

.PHONY: cdp
cdp:
	gcc -ggdb3 -Wall -o cdp sc_map.c parser.c context.c strbuf.c
