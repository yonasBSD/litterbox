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
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <tls.h>
#include <unistd.h>

#include "database.h"

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
static enum {
	None,
	Private,
	Public,
} searchQuery;

static char *self;
static char *network;
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
			set(&network, msg->params[i]);
		} else if (!strcmp(key, "CHANTYPES")) {
			set(&chanTypes, msg->params[i]);
		} else if (!strcmp(key, "PREFIX")) {
			strsep(&msg->params[i], ")");
			if (!msg->params[i]) continue;
			set(&prefixes, msg->params[i]);
		}
	}
}

static struct {
	char *buf;
	size_t cap, len;
} motd;

static void handleReplyMOTDStart(struct Message *msg) {
	(void)msg;
	motd.len = 0;
	motd.cap = 80;
	motd.buf = malloc(motd.cap);
	if (!motd.buf) err(EX_OSERR, "malloc");
}

static void handleReplyMOTD(struct Message *msg) {
	require(msg, false, 2);
	char *line = msg->params[1];
	if (!strncmp(line, "- ", 2)) line += 2;
	size_t len = strlen(line);
	if (motd.len + len + 1 > motd.cap) {
		motd.cap *= 2;
		motd.buf = realloc(motd.buf, motd.cap);
		if (!motd.buf) err(EX_OSERR, "realloc");
	}
	memcpy(&motd.buf[motd.len], line, len);
	motd.len += len;
	motd.buf[motd.len++] = '\n';
}

static void handleReplyEndOfMOTD(struct Message *msg) {
	const char *sql = SQL(
		INSERT OR IGNORE INTO motds (time, network, motd)
		VALUES (coalesce(datetime(:time), datetime('now')), :network, :motd);
	);
	sqlite3_stmt *stmt = dbPrepare(sql);
	dbBindText(stmt, ":time", msg->time);
	dbBindText(stmt, ":network", network);
	dbBindTextLen(stmt, ":motd", motd.buf, motd.len);
	dbRun(stmt);
	sqlite3_finalize(stmt);
	free(motd.buf);
	memset(&motd, 0, sizeof(motd));
}

static void insertContext(const char *context, bool query) {
	static sqlite3_stmt *stmt;
	const char *sql = SQL(
		INSERT OR IGNORE INTO contexts (network, name, query)
		VALUES (:network, :context, :query);
	);
	dbPersist(&stmt, sql);
	dbBindText(stmt, ":network", network);
	dbBindText(stmt, ":context", context);
	dbBindInt(stmt, ":query", query);
	dbRun(stmt);
}

static void insertName(const struct Message *msg) {
	static sqlite3_stmt *stmt;
	const char *sql = SQL(
		INSERT OR IGNORE INTO names (nick, user, host)
		VALUES (:nick, :user, :host);
	);
	dbPersist(&stmt, sql);
	dbBindText(stmt, ":nick", msg->nick);
	dbBindText(stmt, ":user", msg->user);
	dbBindText(stmt, ":host", msg->host);
	dbRun(stmt);
}

static void insertEvent(
	const struct Message *msg, enum Type type, const char *context,
	const char *target, const char *message
) {
	static sqlite3_stmt *stmt;
	const char *sql = SQL(
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
	dbPersist(&stmt, sql);
	dbBindText(stmt, ":time", msg->time);
	dbBindInt(stmt, ":type", type);
	dbBindText(stmt, ":network", network);
	dbBindText(stmt, ":context", context);
	dbBindText(stmt, ":nick", msg->nick);
	dbBindText(stmt, ":user", msg->user);
	dbBindText(stmt, ":host", msg->host);
	dbBindText(stmt, ":target", target);
	dbBindText(stmt, ":message", message);
	dbRun(stmt);
}

static void querySearch(struct Message *msg) {
	static sqlite3_stmt *stmt;
	const char *sql = SQL(
		WITH results AS (
			SELECT
				contexts.name AS context,
				date(events.time) || 'T' || time(events.time) || 'Z' AS time,
				events.type,
				names.nick, // TODO: names.user for coloring?
				events.target,
				highlight(search, 6, :bold, :bold)
			FROM events
			JOIN contexts ON contexts.context = events.context
			JOIN names ON names.name = events.name
			JOIN search ON search.rowid = events.event
			WHERE contexts.network = :network
				AND coalesce(contexts.query = :query, true)
				AND search MATCH :search
			ORDER BY events.time DESC, events.event DESC
			LIMIT 10
		)
		SELECT * FROM results ORDER BY context, time;
	);
	dbPersist(&stmt, sql);
	dbBindText(stmt, ":bold", "\2");

	dbBindText(stmt, ":network", network);
	if (searchQuery == Public) {
		dbBindInt(stmt, ":query", false);
	} else {
		dbBindNull(stmt, ":query");
	}
	dbBindText(stmt, ":search", msg->params[1]);

	int result;
	while (SQLITE_ROW == (result = sqlite3_step(stmt))) {
		const char *context = (const char *)sqlite3_column_text(stmt, 0);
		const char *time = (const char *)sqlite3_column_text(stmt, 1);
		enum Type type = sqlite3_column_int(stmt, 2);
		const char *nick = (const char *)sqlite3_column_text(stmt, 3);
		const char *target = (const char *)sqlite3_column_text(stmt, 4);
		const char *message = (const char *)sqlite3_column_text(stmt, 5);
		if (!target) target = "";
		if (!message) message = "";

		format("PRIVMSG %s :(%s) [%s] ", msg->nick, context, time);
		switch (type) {
			break; case Privmsg: format("<%s> %s\r\n", nick, message);
			break; case Notice:  format("-%s- %s\r\n", nick, message);
			break; case Action:  format("* %s %s\r\n", nick, message);
			break; case Join:    format("%s joined\r\n", nick);
			break; case Part:    format("%s parted: %s\r\n", nick, message);
			break; case Quit:    format("%s quit: %s\r\n", nick, message);
			break; case Kick: {
				format("%s kicked %s: %s\r\n", nick, target, message);
			}
			break; case Nick: {
				format("%s changed nick to %s\r\n", nick, target);
			}
			break; case Topic: {
				format("%s set the topic: %s\r\n", nick, message);
			}
		}
	}
	if (result != SQLITE_DONE) warnx("%s", sqlite3_errmsg(db));

	sqlite3_reset(stmt);
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

	if (query && searchQuery && type == Privmsg) {
		if (searchQuery == Public || !strcmp(msg->nick, msg->params[0])) {
			querySearch(msg);
			return;
		}
	}

	insertContext(context, query);
	insertName(msg);
	insertEvent(msg, type, context, NULL, message);
}

static void insertTopic(
	const char *time, const char *context, const char *topic
) {
	static sqlite3_stmt *stmt;
	const char *sql = SQL(
		INSERT OR IGNORE INTO topics (time, context, topic)
		SELECT coalesce(datetime(:time), datetime('now')), context, :topic
		FROM contexts WHERE network = :network AND name = :context;
	);
	dbPersist(&stmt, sql);
	dbBindText(stmt, ":time", time);
	dbBindText(stmt, ":network", network);
	dbBindText(stmt, ":context", context);
	dbBindText(stmt, ":topic", topic);
	dbRun(stmt);
}

static void handleReplyTopic(struct Message *msg) {
	require(msg, false, 2);
	if (!strcmp(msg->cmd, "331")) msg->params[2] = "";
	insertContext(msg->params[1], false);
	insertTopic(msg->time, msg->params[1], msg->params[2]);
}

static void createJoins(void) {
	const char *sql = SQL(
		CREATE TEMPORARY TABLE joins (
			nick TEXT NOT NULL,
			channel TEXT NOT NULL,
			UNIQUE (nick, channel)
		);
	);
	dbExec(sql);
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
	insertName(msg);
	insertEvent(msg, Join, msg->params[0], NULL, NULL);
	insertJoin(msg->nick, msg->params[0]);
}

static void handlePart(struct Message *msg) {
	require(msg, true, 1);
	insertContext(msg->params[0], false);
	insertName(msg);
	insertEvent(msg, Part, msg->params[0], NULL, msg->params[1]);
	if (!strcmp(msg->nick, self)) {
		clearJoins(NULL, msg->params[0]);
	} else {
		deleteJoin(msg->nick, msg->params[0]);
	}
}

static void handleKick(struct Message *msg) {
	require(msg, true, 2);
	insertContext(msg->params[0], false);
	insertName(msg);
	insertEvent(msg, Kick, msg->params[0], msg->params[1], msg->params[2]);
	if (!strcmp(msg->params[1], self)) {
		clearJoins(NULL, msg->params[0]);
	} else {
		deleteJoin(msg->params[1], msg->params[0]);
	}
}

static void insertEvents(
	const struct Message *msg, enum Type type,
	const char *target, const char *message
) {
	static sqlite3_stmt *stmt;
	const char *sql = SQL(
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
	dbPersist(&stmt, sql);
	dbBindText(stmt, ":time", msg->time);
	dbBindInt(stmt, ":type", type);
	dbBindText(stmt, ":network", network);
	dbBindText(stmt, ":nick", msg->nick);
	dbBindText(stmt, ":user", msg->user);
	dbBindText(stmt, ":host", msg->host);
	dbBindText(stmt, ":target", target);
	dbBindText(stmt, ":message", message);
	dbRun(stmt);
}

static void handleNick(struct Message *msg) {
	require(msg, true, 1);
	if (!strcmp(msg->nick, self)) set(&self, msg->params[0]);
	insertName(msg);
	insertEvents(msg, Nick, msg->params[0], NULL);
	static sqlite3_stmt *stmt;
	const char *sql = SQL(
		UPDATE joins SET nick = :new WHERE nick = :old;
	);
	dbPersist(&stmt, sql);
	dbBindText(stmt, ":old", msg->nick);
	dbBindText(stmt, ":new", msg->params[0]);
	dbRun(stmt);
}

static void handleQuit(struct Message *msg) {
	require(msg, true, 0);
	insertName(msg);
	insertEvents(msg, Quit, NULL, msg->params[0]);
	clearJoins(msg->nick, NULL);
}

static void handleTopic(struct Message *msg) {
	require(msg, true, 1);
	insertContext(msg->params[0], false);
	insertTopic(msg->time, msg->params[0], msg->params[1]);
	insertName(msg);
	insertEvent(msg, Topic, msg->params[0], NULL, msg->params[1]);
}

static void handlePing(struct Message *msg) {
	require(msg, false, 1);
	format("PONG :%s\r\n", msg->params[0]);
}

static void handleError(struct Message *msg) {
	require(msg, false, 1);
	tls_close(client);
	dbClose();
	errx(EX_UNAVAILABLE, "%s", msg->params[0]);
}

static const struct Handler {
	const char *cmd;
	bool transaction;
	Handler *fn;
} Handlers[] = {
	{ "001", false, handleReplyWelcome },
	{ "005", false, handleReplyISupport },
	{ "331", true, handleReplyTopic },
	{ "332", true, handleReplyTopic },
	{ "353", true, handleReplyNames },
	{ "372", false, handleReplyMOTD },
	{ "375", false, handleReplyMOTDStart },
	{ "376", true, handleReplyEndOfMOTD },
	{ "CAP", false, handleCap },
	{ "ERROR", false, handleError },
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

static int compar(const void *cmd, const void *_handler) {
	const struct Handler *handler = _handler;
	return strcmp(cmd, handler->cmd);
}

static void handle(struct Message msg) {
	if (!msg.cmd) return;
	const struct Handler *handler = bsearch(
		msg.cmd, Handlers, ARRAY_LEN(Handlers), sizeof(*handler), compar
	);
	if (!handler) return;
	if (handler->transaction) {
		dbExec(SQL(BEGIN TRANSACTION;));
		handler->fn(&msg);
		dbExec(SQL(COMMIT TRANSACTION;));
	} else {
		handler->fn(&msg);
	}
}

static void quit(int sig) {
	(void)sig;
	format("QUIT\r\n");
	tls_close(client);
	dbClose();
	_exit(EX_OK);
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
	while (0 < (opt = getopt(argc, argv, "!Qd:h:ij:mn:p:qu:vw:"))) {
		switch (opt) {
			break; case '!': insecure = true;
			break; case 'Q': searchQuery = Public;
			break; case 'd': path = optarg;
			break; case 'h': host = optarg;
			break; case 'i': init = true;
			break; case 'j': join = optarg;
			break; case 'm': migrate = true;
			break; case 'n': nick = optarg;
			break; case 'p': port = optarg;
			break; case 'q': searchQuery = Private;
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
	createJoins();

	if (!host) errx(EX_USAGE, "host required");
	set(&self, "*");
	set(&chanTypes, "#&");
	set(&prefixes, "@+");

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

	signal(SIGINT, quit);
	signal(SIGTERM, quit);

	char buf[8191 + 512];
	size_t len = 0;
	for (;;) {
		ssize_t ret = tls_read(client, &buf[len], sizeof(buf) - len);
		if (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT) continue;
		if (ret < 0) errx(EX_IOERR, "tls_read: %s", tls_error(client));
		if (!ret) errx(EX_PROTOCOL, "server closed connection");
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
}
