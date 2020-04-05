PREFIX = /usr/local
MANDIR = ${PREFIX}/share/man
ETCDIR = ${PREFIX}/etc

CFLAGS += -std=c11 -Wall -Wextra -Wpedantic
LDLIBS = -lsqlite3
LDLIBS_litterbox = -ltls

BINS = litterbox scoop unscoop
MANS = ${BINS:=.1}
RCS  =

-include config.mk

FORMATS = generic catgirl irc textual
OBJS_litterbox = litterbox.o config.o

dev: tags all test

all: ${BINS}

litterbox: ${OBJS_litterbox}
	${CC} ${LDFLAGS} ${OBJS_$@} ${LDLIBS} ${LDLIBS_$@} -o $@

.o:
	${CC} ${LDFLAGS} $< ${LDLIBS} ${LDLIBS_$@} -o $@

${BINS:=.o}: database.h

test: .test

.test: unscoop
	set -e; for format in ${FORMATS}; do ./unscoop -n -f $$format; done
	touch .test

tags: *.c *.h
	ctags -w *.c *.h

clean:
	rm -f .test tags ${BINS} ${OBJS_litterbox} ${BINS:=.o}

install: ${BINS} ${MANS}
	install -d ${PREFIX}/bin ${MANDIR}/man1
	install ${BINS} ${PREFIX}/bin
	for man in ${MANS}; do gzip -c $$man > ${MANDIR}/man1/$$man.gz; done
	if [ -n '${RCS}' ]; then install -d ${ETCDIR}/rc.d; fi
	if [ -n '${RCS}' ]; then install ${RCS} ${ETCDIR}/rc.d; fi

uninstall:
	rm -f ${BINS:%=${PREFIX}/bin/%} ${MANS:%=${MANDIR}/man1/%.gz}
	if [ -n '${RCS}' ]; then rm -f ${RCS:%=${ETCDIR}/%}; fi
