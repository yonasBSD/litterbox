/* Copyright (C) 2019  C. McEnroe <june@causal.agency>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <err.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <tls.h>
#include <unistd.h>

#include "database.h"

static sqlite3 *db;
static struct tls *client;
static bool verbose;

static void writeAll(const char *ptr, size_t len) {
	while (len) {
		ssize_t ret = tls_write(client, ptr, len);
		if (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT) continue;
		if (ret < 0) errx(EX_IOERR, "tls_write: %s", tls_error(client));
		ptr += ret;
		len -= ret;
	}
}

static void format(const char *format, ...) {
	char buf[1024];
	va_list ap;
	va_start(ap, format);
	int len = vsnprintf(buf, sizeof(buf), format, ap);
	va_end(ap);
	assert((size_t)len < sizeof(buf));
	if (verbose) printf("%s", buf);
	writeAll(buf, len);
}

enum { ParamCap = 15 };
struct Message {
	char *time;
	char *nick;
	char *user;
	char *host;
	char *cmd;
	char *params[ParamCap];
};

static struct Message parse(char *line) {
	if (verbose) fprintf(stderr, "%s\n", line);
	struct Message msg = {0};
	if (line[0] == '@') {
		char *tags = 1 + strsep(&line, " ");
		while (tags) {
			char *tag = strsep(&tags, ";");
			char *key = strsep(&tag, "=");
			if (!strcmp(key, "time")) msg.time = tag;
		}
	}
	if (line[0] == ':') {
		char *origin = 1 + strsep(&line, " ");
		msg.nick = strsep(&origin, "!");
		msg.user = strsep(&origin, "@");
		if (origin) {
			msg.host = origin;
		} else {
			msg.host = msg.nick;
			msg.nick = NULL;
		}
	}
	msg.cmd = strsep(&line, " ");
	for (size_t i = 0; line && i < ParamCap; ++i) {
		if (line[0] == ':') {
			msg.params[i] = &line[1];
			break;
		}
		msg.params[i] = strsep(&line, " ");
	}
	return msg;
}

static void require(const struct Message *msg, size_t len) {
	for (size_t i = 0; i < len; ++i) {
		if (msg->params[i]) continue;
		errx(EX_PROTOCOL, "%s missing parameter %zu", msg->cmd, 1 + i);
	}
}

static sqlite3_stmt *insertContext;
static sqlite3_stmt *insertName;
static sqlite3_stmt *insertEvent;

static void prepareInsert(void) {
	const char *InsertContext = SQL(
		INSERT OR IGNORE INTO contexts (network, name, query)
		VALUES (:network, :context, :query);
	);
	insertContext = dbPrepare(db, SQLITE_PREPARE_PERSISTENT, InsertContext);

	const char *InsertName = SQL(
		INSERT OR IGNORE INTO names (nick, user, host)
		VALUES (:nick, :user, :host);
	);
	insertName = dbPrepare(db, SQLITE_PREPARE_PERSISTENT, InsertName);

	const char *InsertEvent = SQL(
		INSERT INTO events (time, type, context, name, target, message)
		SELECT
			coalesce(datetime(:time), datetime('now')),
			:type, context, names.name, :target, :message
		FROM contexts, names
		WHERE contexts.network = :network
			AND contexts.name = :context
			AND names.nick = :nick
			AND names.user = :user
			AND names.host = :host;
	);
	insertEvent = dbPrepare(db, SQLITE_PREPARE_PERSISTENT, InsertEvent);
}

static void bindNetwork(const char *network) {
	dbBindTextCopy(insertContext, ":network", network);
	dbBindTextCopy(insertEvent, ":network", network);
}
static void bindContext(const char *context, bool query) {
	dbBindText(insertContext, ":context", context);
	dbBindInt(insertContext, ":query", query);
	dbBindText(insertEvent, ":context", context);
}
static void bindName(const char *nick, const char *user, const char *host) {
	dbBindText(insertName, ":nick", nick);
	dbBindText(insertName, ":user", user);
	dbBindText(insertName, ":host", host);
	dbBindText(insertEvent, ":nick", nick);
	dbBindText(insertEvent, ":user", user);
	dbBindText(insertEvent, ":host", host);
}

static void printSQL(sqlite3_stmt *stmt) {
	char *sql = sqlite3_expanded_sql(stmt);
	if (!sql) return;
	fprintf(stderr, "%s\n", sql);
	sqlite3_free(sql);
}

static void insert(void) {
	dbExec(db, SQL(BEGIN TRANSACTION;));

	dbStep(insertContext);
	if (verbose && sqlite3_changes(db)) printSQL(insertContext);

	dbStep(insertName);
	if (verbose && sqlite3_changes(db)) printSQL(insertName);

	dbStep(insertEvent);
	if (verbose) printSQL(insertEvent);

	dbExec(db, SQL(COMMIT TRANSACTION;));

	sqlite3_reset(insertContext);
	sqlite3_reset(insertName);
	sqlite3_reset(insertEvent);
	bindContext(NULL, false);
	bindName(NULL, NULL, NULL);
	dbBindNull(insertEvent, ":time");
	dbBindNull(insertEvent, ":type");
	dbBindNull(insertEvent, ":target");
	dbBindNull(insertEvent, ":message");
}

static const char *join;

static char *self;
static char *chanTypes;
static char *prefixes;

static void set(char **field, const char *value) {
	free(*field);
	*field = strdup(value);
	if (!*field) err(EX_OSERR, "strdup");
}

typedef void Handler(struct Message *msg);

static void handleCap(struct Message *msg) {
	(void)msg;
	format("CAP END\r\n");
}

static void handleReplyWelcome(struct Message *msg) {
	require(msg, 1);
	set(&self, msg->params[0]);
	format("JOIN :%s\r\n", join);
}

static void handleReplyISupport(struct Message *msg) {
	for (size_t i = 0; i < ParamCap; ++i) {
		if (!msg->params[i]) break;
		char *key = strsep(&msg->params[i], "=");
		if (!msg->params[i]) continue;
		if (!strcmp(key, "NETWORK")) {
			bindNetwork(msg->params[i]);
		} else if (!strcmp(key, "CHANTYPES")) {
			set(&chanTypes, msg->params[i]);
		} else if (!strcmp(key, "PREFIX")) {
			strsep(&msg->params[i], ")");
			if (!msg->params[i]) continue;
			set(&prefixes, msg->params[i]);
		}
	}
}

static void handlePrivmsg(struct Message *msg) {
	require(msg, 2);
	if (!msg->nick) return;

	bindName(msg->nick, msg->user, msg->host);
	if (strchr(chanTypes, msg->params[0][0])) {
		bindContext(msg->params[0], false);
	} else if (strcmp(msg->params[0], self)) {
		bindContext(msg->params[0], true);
	} else {
		bindContext(msg->nick, true);
	}

	dbBindText(insertEvent, ":time", msg->time);
	dbBindText(insertEvent, ":message", msg->params[1]);
	if (!strncmp(msg->params[1], "\1ACTION ", 8)) {
		msg->params[1] += 8;
		msg->params[1][strcspn(msg->params[1], "\1")] = '\0';
		dbBindInt(insertEvent, ":type", Action);
		dbBindText(insertEvent, ":message", msg->params[1]);
	} else if (!strcmp(msg->cmd, "NOTICE")) {
		dbBindInt(insertEvent, ":type", Notice);
	} else {
		dbBindInt(insertEvent, ":type", Privmsg);
	}

	insert();
}

static void handlePing(struct Message *msg) {
	require(msg, 1);
	format("PONG :%s\r\n", msg->params[0]);
}

static const struct {
	const char *cmd;
	Handler *fn;
} Handlers[] = {
	{ "001", handleReplyWelcome },
	{ "005", handleReplyISupport },
	{ "CAP", handleCap },
	{ "NOTICE", handlePrivmsg },
	{ "PING", handlePing },
	{ "PRIVMSG", handlePrivmsg },
};

static void handle(struct Message msg) {
	if (!msg.cmd) return;
	for (size_t i = 0; i < ARRAY_LEN(Handlers); ++i) {
		if (strcmp(msg.cmd, Handlers[i].cmd)) continue;
		Handlers[i].fn(&msg);
		break;
	}
}

int main(int argc, char *argv[]) {
	char *path = NULL;
	bool init = false;
	bool migrate = false;

	bool insecure = false;
	const char *host = NULL;
	const char *port = "6697";

	const char *nick = "litterbox";
	const char *user = NULL;
	const char *pass = NULL;

	int opt;
	while (0 < (opt = getopt(argc, argv, "!d:h:ij:mn:p:u:vw:"))) {
		switch (opt) {
			break; case '!': insecure = true;
			break; case 'd': path = optarg;
			break; case 'h': host = optarg;
			break; case 'i': init = true;
			break; case 'j': join = optarg;
			break; case 'm': migrate = true;
			break; case 'n': nick = optarg;
			break; case 'p': port = optarg;
			break; case 'u': user = optarg;
			break; case 'v': verbose = true;
			break; case 'w': pass = optarg;
			break; default:  return EX_USAGE;
		}
	}
	if (!user) user = nick;

	int flags = SQLITE_OPEN_READWRITE;
	if (init) flags |= SQLITE_OPEN_CREATE;

	db = (path ? dbOpen(path, flags) : dbFind(flags));
	if (!db) errx(EX_NOINPUT, "database not found");

	if (init) {
		dbInit(db);
		return EX_OK;
	}
	if (migrate) {
		dbMigrate(db);
		return EX_OK;
	}
	if (dbVersion(db) != DatabaseVersion) {
		errx(EX_CONFIG, "database out of date; migrate with -m");
	}

	if (!host) errx(EX_USAGE, "host required");
	set(&chanTypes, "#&");
	set(&prefixes, "@+");

	prepareInsert();
	bindNetwork(host);

	client = tls_client();
	if (!client) errx(EX_SOFTWARE, "tls_client");

	struct tls_config *config = tls_config_new();
	if (!config) errx(EX_SOFTWARE, "tls_config_new");

	int error = tls_config_set_ciphers(config, "compat");
	if (error) {
		errx(EX_SOFTWARE, "tls_config_set_ciphers: %s", tls_config_error(config));
	}
	if (insecure) {
		tls_config_insecure_noverifycert(config);
		tls_config_insecure_noverifyname(config);
	}

	error = tls_configure(client, config);
	if (error) errx(EX_SOFTWARE, "tls_configure: %s", tls_error(client));
	tls_config_free(config);

	error = tls_connect(client, host, port);
	if (error) errx(EX_UNAVAILABLE, "tls_connect: %s", tls_error(client));

	if (pass) format("PASS :%s\r\n", pass);
	format("CAP REQ :server-time\r\n");
	format("NICK :%s\r\nUSER %s 0 * :Litterbox\r\n", nick, user);

	char buf[8191 + 512];
	size_t len = 0;
	for (;;) {
		ssize_t ret = tls_read(client, &buf[len], sizeof(buf) - len);
		if (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT) continue;
		if (ret < 0) errx(EX_IOERR, "tls_read: %s", tls_error(client));
		len += ret;

		char *line = buf;
		for (;;) {
			char *crlf = memmem(line, &buf[len] - line, "\r\n", 2);
			if (!crlf) break;
			crlf[0] = '\0';
			handle(parse(line));
			line = crlf + 2;
		}
		len -= line - buf;
		memmove(buf, line, len);
	}

	// TODO: Clean up statements and db on exit.
}
