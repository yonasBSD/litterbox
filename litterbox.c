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

static bool verbose;

static void printSQL(sqlite3_stmt *stmt) {
	if (!verbose) return;
	char *sql = sqlite3_expanded_sql(stmt);
	if (!sql) return;
	fprintf(stderr, "%s\n", sql);
	sqlite3_free(sql);
}

static sqlite3 *db;

static const char *CreateJoins = SQL(
	CREATE TEMPORARY TABLE joins (
		nick TEXT NOT NULL,
		channel TEXT NOT NULL,
		UNIQUE (nick, channel)
	);
);

enum {
	InsertContext,
	InsertName,
	InsertEvent,
	InsertJoin,
	DeleteJoin,
	UpdateJoin,
	InsertEvents,
};
static const char *Statements[] = {
	[InsertContext] = SQL(
		INSERT OR IGNORE INTO contexts (network, name, query)
		VALUES (:network, :context, :query);
	),

	[InsertName] = SQL(
		INSERT OR IGNORE INTO names (nick, user, host)
		VALUES (:nick, :user, :host);
	),

	[InsertEvent] = SQL(
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
	),

	[InsertEvents] = SQL(
		INSERT INTO events (time, type, context, name, target, message)
		SELECT
			coalesce(datetime(:time), datetime('now')),
			:type, context, names.name, :target, :message
		FROM joins, contexts, names
		WHERE joins.nick = :nick
			AND contexts.name = joins.channel
			AND contexts.network = :network
			AND names.nick = :nick
			AND names.user = :user
			AND names.host = :host;
	),

	[InsertJoin] = SQL(
		INSERT INTO joins (nick, channel) VALUES (:nick, :channel);
	),
	[DeleteJoin] = SQL(
		DELETE FROM joins WHERE nick = :nick AND channel = :channel;
	),
	[UpdateJoin] = SQL(
		UPDATE joins SET nick = :new WHERE nick = :old;
	),
};

static sqlite3_stmt *stmts[ARRAY_LEN(Statements)];

static void prepare(void) {
	dbExec(db, CreateJoins);
	for (size_t i = 0; i < ARRAY_LEN(stmts); ++i) {
		stmts[i] = dbPrepare(db, true, Statements[i]);
	}
}

static void bindNetwork(const char *network) {
	dbBindTextCopy(stmts[InsertContext], ":network", network);
	dbBindTextCopy(stmts[InsertEvent], ":network", network);
	dbBindTextCopy(stmts[InsertEvents], ":network", network);
}

static void insertContext(const char *context, bool query) {
	dbBindText(stmts[InsertContext], ":context", context);
	dbBindInt(stmts[InsertContext], ":query", query);
	dbStep(stmts[InsertContext]);
	dbBindText(stmts[InsertEvent], ":context", context);
	if (sqlite3_changes(db)) printSQL(stmts[InsertContext]);
	sqlite3_reset(stmts[InsertContext]);
}

static void insertName(const char *nick, const char *user, const char *host) {
	dbBindText(stmts[InsertName], ":nick", nick);
	dbBindText(stmts[InsertName], ":user", user);
	dbBindText(stmts[InsertName], ":host", host);
	dbStep(stmts[InsertName]);
	dbBindText(stmts[InsertEvent], ":nick", nick);
	dbBindText(stmts[InsertEvent], ":user", user);
	dbBindText(stmts[InsertEvent], ":host", host);
	dbBindText(stmts[InsertEvents], ":nick", nick);
	dbBindText(stmts[InsertEvents], ":user", user);
	dbBindText(stmts[InsertEvents], ":host", host);
	if (sqlite3_changes(db)) printSQL(stmts[InsertName]);
	sqlite3_reset(stmts[InsertName]);
}

static void insertEvent(
	const char *time, enum Type type, const char *target, const char *message
) {
	dbBindText(stmts[InsertEvent], ":time", time);
	dbBindInt(stmts[InsertEvent], ":type", type);
	dbBindText(stmts[InsertEvent], ":target", target);
	dbBindText(stmts[InsertEvent], ":message", message);
	dbStep(stmts[InsertEvent]);
	printSQL(stmts[InsertEvent]);
	sqlite3_reset(stmts[InsertEvent]);
}

static void insertEvents(
	const char *time, enum Type type, const char *target, const char *message
) {
	dbBindText(stmts[InsertEvents], ":time", time);
	dbBindInt(stmts[InsertEvents], ":type", type);
	dbBindText(stmts[InsertEvents], ":target", target);
	dbBindText(stmts[InsertEvents], ":message", message);
	dbStep(stmts[InsertEvents]);
	printSQL(stmts[InsertEvents]);
	sqlite3_reset(stmts[InsertEvents]);
}

static void insertJoin(const char *nick, const char *channel) {
	dbBindText(stmts[InsertJoin], ":nick", nick);
	dbBindText(stmts[InsertJoin], ":channel", channel);
	dbStep(stmts[InsertJoin]);
	printSQL(stmts[InsertJoin]);
	sqlite3_reset(stmts[InsertJoin]);
}

static void deleteJoin(const char *nick, const char *channel) {
	dbBindText(stmts[DeleteJoin], ":nick", nick);
	dbBindText(stmts[DeleteJoin], ":channel", channel);
	dbStep(stmts[DeleteJoin]);
	printSQL(stmts[DeleteJoin]);
	sqlite3_reset(stmts[DeleteJoin]);
}

static void updateJoin(const char *old, const char *new) {
	dbBindText(stmts[UpdateJoin], ":old", old);
	dbBindText(stmts[UpdateJoin], ":new", new);
	dbStep(stmts[UpdateJoin]);
	printSQL(stmts[UpdateJoin]);
	sqlite3_reset(stmts[UpdateJoin]);
}

static struct tls *client;

static void clientWrite(const char *ptr, size_t len) {
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
	clientWrite(buf, len);
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

	insertName(msg->nick, msg->user, msg->host);
	if (strchr(chanTypes, msg->params[0][0])) {
		insertContext(msg->params[0], false);
	} else if (strcmp(msg->params[0], self)) {
		insertContext(msg->params[0], true);
	} else {
		insertContext(msg->nick, true);
	}

	if (!strncmp(msg->params[1], "\1ACTION ", 8)) {
		char *action = &msg->params[1][8];
		action[strcspn(action, "\1")] = '\0';
		insertEvent(msg->time, Action, NULL, action);
	} else if (!strcmp(msg->cmd, "NOTICE")) {
		insertEvent(msg->time, Notice, NULL, msg->params[1]);
	} else {
		insertEvent(msg->time, Privmsg, NULL, msg->params[1]);
	}
}

static void handleJoin(struct Message *msg) {
	require(msg, 1);
	insertContext(msg->params[0], false);
	insertName(msg->nick, msg->user, msg->host);
	insertEvent(msg->time, Join, NULL, NULL);
	insertJoin(msg->nick, msg->params[0]);
}

static void handlePart(struct Message *msg) {
	require(msg, 1);
	insertContext(msg->params[0], false);
	insertName(msg->nick, msg->user, msg->host);
	insertEvent(msg->time, Part, NULL, msg->params[1]);
	deleteJoin(msg->nick, msg->params[0]);
	// TODO: Clear joins if self.
}

static void handleKick(struct Message *msg) {
	require(msg, 2);
	insertContext(msg->params[0], false);
	insertName(msg->nick, msg->user, msg->host);
	insertEvent(msg->time, Kick, msg->params[1], msg->params[2]);
	deleteJoin(msg->params[1], msg->params[0]);
	// TODO: Clear joins if self.
}

static void handleNick(struct Message *msg) {
	require(msg, 1);
	if (!strcmp(msg->nick, self)) set(&self, msg->params[0]);
	insertName(msg->nick, msg->user, msg->host);
	insertEvents(msg->time, Nick, msg->params[0], NULL);
	updateJoin(msg->nick, msg->params[0]);
}

static void handlePing(struct Message *msg) {
	require(msg, 1);
	format("PONG :%s\r\n", msg->params[0]);
}

static const struct {
	const char *cmd;
	bool transaction;
	Handler *fn;
} Handlers[] = {
	{ "001", false, handleReplyWelcome },
	{ "005", false, handleReplyISupport },
	{ "CAP", false, handleCap },
	{ "JOIN", true, handleJoin },
	{ "KICK", true, handleKick },
	{ "NICK", true, handleNick },
	{ "NOTICE", true, handlePrivmsg },
	{ "PART", true, handlePart },
	{ "PING", false, handlePing },
	{ "PRIVMSG", true, handlePrivmsg },
};

static void handle(struct Message msg) {
	if (!msg.cmd) return;
	for (size_t i = 0; i < ARRAY_LEN(Handlers); ++i) {
		if (strcmp(msg.cmd, Handlers[i].cmd)) continue;
		dbExec(db, SQL(BEGIN TRANSACTION;));
		Handlers[i].fn(&msg);
		dbExec(db, SQL(COMMIT TRANSACTION;));
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

	prepare();
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
