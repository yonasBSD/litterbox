# README(7) 	Miscellaneous Information Manual 	README(7)

## NAME

litterbox — IRC logger

## DESCRIPTION

litterbox(1) is a TLS-only IRC logger. It logs events from IRC in a SQLite database, indexing messages for full-text search. It is intended for use with the IRC bouncer pounce, but can also be used independently as a logging bot.

litterbox provides the scoop(1) command-line query utility. A web interface for litterbox is provided by scooper. Some formats of plain text logs can be imported into the litterbox database with unscoop(1).
INSTALLING

litterbox requires SQLite3 and libtls, provided by either LibreTLS (for OpenSSL) or by LibreSSL. It targets FreeBSD, OpenBSD and Linux.

./configure
make all
sudo make install

If installing libtls manually to /usr/local, for example, make sure /usr/local/lib appears in /etc/ld.so.conf or /etc/ld.so.conf.d/* and be sure to run ldconfig(8) once the library is installed. Set PKG_CONFIG_PATH for ./configure to find it.

PKG_CONFIG_PATH=/usr/local/lib/pkgconfig ./configure

On OpenBSD the recommended way to run litterbox is with the process supervisor kitd.
FILES

database.h
    database functions and schema
litterbox.c
    IRC logging
scoop.c
    query building and output formatting
unscoop.c
    log file processing
config.c
    getopt_long(3)-integrated configuration parsing
xdg.c
    XDG base directories

## CONTRIBUTING

The upstream URL of this project is ⟨https://git.causal.agency/litterbox⟩. Contributions in any form can be sent to <list+litterbox@causal.agency>. For sending patches by email, see ⟨https://git-send-email.io⟩.

Monetary contributions can be donated via Liberapay.

## SEE ALSO

litterbox(1), scoop(1), unscoop(1)

    IRC bouncer: pounce
    Web interface: scooper

    June McEnroe, IRC Suite, https://text.causal.agency/010-irc-suite.txt, June 19, 2020.

October 21, 2023 	Causal Agency
