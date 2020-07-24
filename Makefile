PREFIX ?= /usr/local
MANDIR ?= ${PREFIX}/share/man
ETCDIR ?= ${PREFIX}/etc

CFLAGS += -std=c11 -Wall -Wextra -Wpedantic
LDLIBS = -lsqlite3 -ltls

BINS = litterbox scoop unscoop
MANS = ${BINS:=.1}
RCS  = rc.d/litterbox

-include config.mk

FORMATS = generic catgirl irc textual
OBJS.litterbox = litterbox.o config.o

dev: tags all test

all: ${BINS}

litterbox: ${OBJS.litterbox}
	${CC} ${LDFLAGS} ${OBJS.$@} ${LDLIBS} -o $@

.o:
	${CC} ${LDFLAGS} $< ${LDLIBS} -o $@

${BINS:=.o}: database.h

test: .test

.test: unscoop
	set -e; for format in ${FORMATS}; do ./unscoop -n -f $$format; done
	touch .test

.SUFFIXES: .in

.in:
	sed -e 's|%%PREFIX%%|${PREFIX}|g' $< > $@

tags: *.c *.h
	ctags -w *.c *.h

clean:
	rm -f .test tags ${BINS} ${RCS} ${OBJS.litterbox} ${BINS:=.o}

install: ${BINS} ${MANS} ${INSTALLS}
	install -d ${DESTDIR}${PREFIX}/bin ${DESTDIR}${MANDIR}/man1
	install ${BINS} ${DESTDIR}${PREFIX}/bin
	install -m 644 ${MANS} ${DESTDIR}${MANDIR}/man1

install-rcs: ${RCS}
	install -d ${DESTDIR}${ETCDIR}/rc.d
	install ${RCS} ${DESTDIR}${ETCDIR}/rc.d

uninstall:
	rm -f ${BINS:%=${DESTDIR}${PREFIX}/bin/%}
	rm -f ${MANS:%=${DESTDIR}${MANDIR}/man1/%}
	rm -f ${RCS:%=${DESTDIR}${ETCDIR}/%}
