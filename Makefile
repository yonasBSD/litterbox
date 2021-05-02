PREFIX ?= /usr/local
BINDIR ?= ${PREFIX}/bin
MANDIR ?= ${PREFIX}/man

CFLAGS += -std=c11 -Wall -Wextra -Wpedantic
LDADD.sqlite3 = -lsqlite3
LDADD.libtls = -ltls

BINS = litterbox scoop unscoop
MANS = ${BINS:=.1}

-include config.mk

LDLIBS.litterbox = ${LDADD.sqlite3} ${LDADD.libtls}
LDLIBS.scoop = ${LDADD.sqlite3}
LDLIBS.unscoop = ${LDADD.sqlite3}

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

${BINS}:
	${CC} ${LDFLAGS} ${OBJS.$@} ${LDLIBS.$@} -o $@

${OBJS}: database.h

test: .test

.test: unscoop
	for f in ${FORMATS}; do ./unscoop -! -f $$f || exit 1; done
	touch .test

tags: *.[ch]
	ctags -w *.[ch]

clean:
	rm -f ${BINS} ${OBJS} .test tags

install: ${BINS} ${MANS}
	install -d ${DESTDIR}${BINDIR} ${DESTDIR}${MANDIR}/man1
	install ${BINS} ${DESTDIR}${BINDIR}
	install -m 644 ${MANS} ${DESTDIR}${MANDIR}/man1

uninstall:
	rm -f ${BINS:%=${DESTDIR}${BINDIR}/%}
	rm -f ${MANS:%=${DESTDIR}${MANDIR}/man1/%}
