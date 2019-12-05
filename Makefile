LIBS_PREFIX = /usr/local

CFLAGS += -std=c11 -Wall -Wextra -Wpedantic
CFLAGS += ${LIBS_PREFIX:%=-I%/include}
LDFLAGS += ${LIBS_PREFIX:%=-L%/lib}
LDLIBS = -lsqlite3

BINS = litterbox unscoop

-include config.mk

dev: tags all

all: ${BINS}

${BINS:=.o}: database.h

tags: *.c *.h
	ctags -w *.c *.h

clean:
	rm -f tags ${BINS} ${BINS:=.o}
