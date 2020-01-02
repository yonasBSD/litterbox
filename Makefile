PREFIX = /usr/local
MANDIR = ${PREFIX}/share/man
LIBS_PREFIX = /usr/local

CFLAGS += -std=c11 -Wall -Wextra -Wpedantic
CFLAGS += ${LIBS_PREFIX:%=-I%/include}
LDFLAGS += ${LIBS_PREFIX:%=-L%/lib}
LDLIBS = -lsqlite3
LDLIBS_litterbox = -ltls

BINS = litterbox scoop unscoop
MANS = ${BINS:=.1}

-include config.mk

dev: tags all

all: ${BINS}

${BINS:=.o}: database.h

.o:
	${CC} ${LDFLAGS} $< ${LDLIBS} ${LDLIBS_$@} -o $@

tags: *.c *.h
	ctags -w *.c *.h

clean:
	rm -f tags ${BINS} ${BINS:=.o}

install: ${BINS} ${MANS}
	install -d ${PREFIX}/bin ${MANDIR}/man1
	install ${BINS} ${PREFIX}/bin
	for man in ${MANS}; do gzip -c $$man > ${MANDIR}/man1/$$man.gz; done

uninstall:
	rm -f ${BINS:%=${PREFIX}/bin/%} ${MANS:%=${MANDIR}/man1/%.gz}
