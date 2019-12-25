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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <tls.h>
#include <unistd.h>

#include "database.h"

static struct {
	sqlite3_stmt *context;
	sqlite3_stmt *event;
	sqlite3_stmt *events;
} insert;

static void prepare(void) {
	const char *CreateJoins = SQL(
		CREATE TEMPORARY TABLE joins (
			nick TEXT NOT NULL,
			channel TEXT NOT NULL,
			UNIQUE (nick, channel)
		);
	);
	dbExec(CreateJoins);

	const char *InsertContext = SQL(
		INSERT OR IGNORE INTO contexts (network, name, query)
		VALUES (:network, :context, :query);
	);
	dbPersist(&insert.context, InsertContext);

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
	dbPersist(&insert.event, InsertEvent);

	const char *InsertEvents = SQL(
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
	);
	dbPersist(&insert.events, InsertEvents);
}

static void bindNetwork(const char *network) {
	dbBindTextCopy(insert.context, ":network", network);
	dbBindTextCopy(insert.event, ":network", network);
	dbBindTextCopy(insert.events, ":network", network);
}

static void insertContext(const char *context, bool query) {
	dbBindText(insert.context, ":context", context);
	dbBindInt(insert.context, ":query", query);
	dbRun(insert.context);
}

static void insertEvent(
	const char *time, enum Type type, const char *context,
	const char *nick, const char *user, const char *host,
	const char *target, const char *message
) {
	dbBindText(insert.event, ":time", time);
	dbBindInt(insert.event, ":type", type);
	dbBindText(insert.event, ":context", context);
	dbBindText(insert.event, ":nick", nick);
	dbBindText(insert.event, ":user", user);
	dbBindText(insert.event, ":host", host);
	dbBindText(insert.event, ":target", target);
	dbBindText(insert.event, ":message", message);
	dbRun(insert.event);
}

static void insertEvents(
	const char *time, enum Type type,
	const char *nick, const char *user, const char *host,
	const char *target, const char *message
) {
	dbBindText(insert.events, ":time", time);
	dbBindInt(insert.events, ":type", type);
	dbBindText(insert.events, ":nick", nick);
	dbBindText(insert.events, ":user", user);
	dbBindText(insert.events, ":host", host);
	dbBindText(insert.events, ":target", target);
	dbBindText(insert.events, ":message", message);
	dbRun(insert.events);
}

static void insertName(const char *nick, const char *user, const char *host) {
	static sqlite3_stmt *stmt;
	const char *sql = SQL(
		INSERT OR IGNORE INTO names (nick, user, host)
		VALUES (:nick, :user, :host);
	);
	dbPersist(&stmt, sql);
	dbBindText(stmt, ":nick", nick);
	dbBindText(stmt, ":user", user);
	dbBindText(stmt, ":host", host);
	dbRun(stmt);
}

static void insertJoin(const char *nick, const char *channel) {
	static sqlite3_stmt *stmt;
	const char *sql = SQL(
		INSERT OR IGNORE INTO joins (nick, channel) VALUES (:nick, :channel);
	);
	dbPersist(&stmt, sql);
	dbBindText(stmt, ":nick", nick);
	dbBindText(stmt, ":channel", channel);
	dbRun(stmt);
}

static void deleteJoin(const char *nick, const char *channel) {
	static sqlite3_stmt *stmt;
	const char *sql = SQL(
		DELETE FROM joins WHERE nick = :nick AND channel = :channel;
	);
	dbPersist(&stmt, sql);
	dbBindText(stmt, ":nick", nick);
	dbBindText(stmt, ":channel", channel);
	dbRun(stmt);
}

static void updateJoin(const char *old, const char *new) {
	static sqlite3_stmt *stmt;
	const char *sql = SQL(
		UPDATE joins SET nick = :new WHERE nick = :old;
	);
	dbPersist(&stmt, sql);
	dbBindText(stmt, ":old", old);
	dbBindText(stmt, ":new", new);
	dbRun(stmt);
}

static void clearJoins(const char *nick, const char *channel) {
	static sqlite3_stmt *stmt;
	const char *sql = SQL(
		DELETE FROM joins WHERE nick = :nick OR channel = :channel;
	);
	dbPersist(&stmt, sql);
	dbBindText(stmt, ":nick", nick);
	dbBindText(stmt, ":channel", channel);
	dbRun(stmt);
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
		msg.host = origin;
		if (!msg.user) msg.user = msg.nick;
		if (!msg.host) msg.host = msg.user;
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

static void require(const struct Message *msg, bool nick, size_t len) {
	if (nick && !msg->nick) errx(EX_PROTOCOL, "%s missing origin", msg->cmd);
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
	require(msg, false, 1);
	set(&self, msg->params[0]);
	if (join) format("JOIN :%s\r\n", join);
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
	require(msg, true, 2);

	bool query = true;
	const char *context = msg->params[0];
	if (strchr(chanTypes, context[0])) query = false;
	if (!strcmp(context, self)) context = msg->nick;

	enum Type type = (!strcmp(msg->cmd, "NOTICE") ? Notice : Privmsg);
	char *message = msg->params[1];
	if (!strncmp(message, "\1ACTION ", 8)) {
		message += 8;
		message[strcspn(message, "\1")] = '\0';
		type = Action;
	}

	insertContext(context, query);
	insertName(msg->nick, msg->user, msg->host);
	insertEvent(
		msg->time, type, context,
		msg->nick, msg->user, msg->host, NULL, message
	);
}

static void handleReplyNames(struct Message *msg) {
	require(msg, false, 3);
	char *names = msg->params[3];
	while (names) {
		char *nick = strsep(&names, " ");
		nick += strspn(nick, prefixes);
		insertJoin(nick, msg->params[2]);
	}
}

static void handleJoin(struct Message *msg) {
	require(msg, true, 1);
	insertContext(msg->params[0], false);
	insertName(msg->nick, msg->user, msg->host);
	insertEvent(
		msg->time, Join, msg->params[0],
		msg->nick, msg->user, msg->host, NULL, NULL
	);
	insertJoin(msg->nick, msg->params[0]);
}

static void handlePart(struct Message *msg) {
	require(msg, true, 1);
	insertContext(msg->params[0], false);
	insertName(msg->nick, msg->user, msg->host);
	insertEvent(
		msg->time, Part, msg->params[0],
		msg->nick, msg->user, msg->host, NULL, msg->params[1]
	);
	if (!strcmp(msg->nick, self)) {
		clearJoins(NULL, msg->params[0]);
	} else {
		deleteJoin(msg->nick, msg->params[0]);
	}
}

static void handleKick(struct Message *msg) {
	require(msg, true, 2);
	insertContext(msg->params[0], false);
	insertName(msg->nick, msg->user, msg->host);
	insertEvent(
		msg->time, Kick, msg->params[0],
		msg->nick, msg->user, msg->host,
		msg->params[1], msg->params[2]
	);
	if (!strcmp(msg->params[1], self)) {
		clearJoins(NULL, msg->params[0]);
	} else {
		deleteJoin(msg->params[1], msg->params[0]);
	}
}

static void handleNick(struct Message *msg) {
	require(msg, true, 1);
	if (!strcmp(msg->nick, self)) set(&self, msg->params[0]);
	insertName(msg->nick, msg->user, msg->host);
	insertEvents(
		msg->time, Nick,
		msg->nick, msg->user, msg->host, msg->params[0], NULL
	);
	updateJoin(msg->nick, msg->params[0]);
}

static void handleQuit(struct Message *msg) {
	require(msg, true, 0);
	insertName(msg->nick, msg->user, msg->host);
	insertEvents(
		msg->time, Quit,
		msg->nick, msg->user, msg->host, NULL, msg->params[0]
	);
	clearJoins(msg->nick, NULL);
}

static void handleTopic(struct Message *msg) {
	require(msg, true, 1);
	insertContext(msg->params[0], false);
	insertName(msg->nick, msg->user, msg->host);
	insertEvent(
		msg->time, Topic, msg->params[0],
		msg->nick, msg->user, msg->host, NULL, msg->params[1]
	);
}

static void handlePing(struct Message *msg) {
	require(msg, false, 1);
	format("PONG :%s\r\n", msg->params[0]);
}

static const struct {
	const char *cmd;
	bool transaction;
	Handler *fn;
} Handlers[] = {
	{ "001", false, handleReplyWelcome },
	{ "005", false, handleReplyISupport },
	{ "353", true, handleReplyNames },
	{ "CAP", false, handleCap },
	{ "JOIN", true, handleJoin },
	{ "KICK", true, handleKick },
	{ "NICK", true, handleNick },
	{ "NOTICE", true, handlePrivmsg },
	{ "PART", true, handlePart },
	{ "PING", false, handlePing },
	{ "PRIVMSG", true, handlePrivmsg },
	{ "QUIT", true, handleQuit },
	{ "TOPIC", true, handleTopic },
};

static void handle(struct Message msg) {
	if (!msg.cmd) return;
	for (size_t i = 0; i < ARRAY_LEN(Handlers); ++i) {
		if (strcmp(msg.cmd, Handlers[i].cmd)) continue;
		if (Handlers[i].transaction) {
			dbExec(SQL(BEGIN TRANSACTION;));
			Handlers[i].fn(&msg);
			dbExec(SQL(COMMIT TRANSACTION;));
		} else {
			Handlers[i].fn(&msg);
		}
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
	dbFind(path, flags);

	if (init) {
		dbInit();
		return EX_OK;
	}
	if (migrate) {
		dbMigrate();
		return EX_OK;
	}
	if (dbVersion() != DatabaseVersion) {
		errx(EX_CONFIG, "database out of date; migrate with -m");
	}

	if (!host) errx(EX_USAGE, "host required");
	set(&self, "*");
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
		if (!ret) break;
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

	dbClose();
}
