PREFIX ?= /usr/local
MANDIR ?= ${PREFIX}/share/man
ETCDIR ?= ${PREFIX}/etc

CFLAGS += -std=c11 -Wall -Wextra -Wpedantic
LDLIBS = -lsqlite3 -ltls

BINS = litterbox scoop unscoop
MANS = ${BINS:=.1}

-include config.mk

OBJS.litterbox = litterbox.o config.o xdg.o
OBJS.scoop = scoop.o xdg.o
OBJS.unscoop = unscoop.o xdg.o
OBJS = ${OBJS.litterbox} ${OBJS.scoop} ${OBJS.unscoop}

FORMATS = generic catgirl irc textual

dev: tags all test

all: ${BINS}

litterbox: ${OBJS.litterbox}

scoop: ${OBJS.scoop}

unscoop: ${OBJS.unscoop}

.o:
	${CC} ${LDFLAGS} ${OBJS.$@} ${LDLIBS} -o $@

${OBJS}: database.h

test: .test

.test: unscoop
	set -e; for format in ${FORMATS}; do ./unscoop -n -f $$format; done
	touch .test

tags: *.[ch]
	ctags -w *.[ch]

clean:
	rm -f ${BINS} ${OBJS} .test tags

install: ${BINS} ${MANS}
	install -d ${DESTDIR}${PREFIX}/bin ${DESTDIR}${MANDIR}/man1
	install ${BINS} ${DESTDIR}${PREFIX}/bin
	install -m 644 ${MANS} ${DESTDIR}${MANDIR}/man1

uninstall:
	rm -f ${BINS:%=${DESTDIR}${PREFIX}/bin/%}
	rm -f ${MANS:%=${DESTDIR}${MANDIR}/man1/%}
