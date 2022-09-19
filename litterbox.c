/* Copyright (C) 2019  June McEnroe <june@causal.agency>
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
 *
 * Additional permission under GNU GPL version 3 section 7:
 *
 * If you modify this Program, or any covered work, by linking or
 * combining it with OpenSSL (or a modified version of that library),
 * containing parts covered by the terms of the OpenSSL License and the
 * original SSLeay license, the licensors of this Program grant you
 * additional permission to convey the resulting work. Corresponding
 * Source for a non-source form of such a combination shall include the
 * source code for the parts of OpenSSL used as well as that of the
 * covered work.
 */

#include <assert.h>
#include <err.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <tls.h>
#include <unistd.h>

#include "database.h"

static const char *host;
static const char *port = "6697";
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
	if (verbose) fprintf(stderr, "%s", buf);
	clientWrite(buf, len);
}

enum { ParamCap = 254 };
struct Message {
	size_t pos;
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
			if (!strcmp(key, "causal.agency/pos")) {
				msg.pos = strtoull(tag, NULL, 10);
			}
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
static int searchLimit = 10;

static char *self;
static char *network;
static char *chanTypes;
static char *statusmsg;
static char *prefixes;
static char *prefixModes;
static char *listModes;
static char *paramModes;
static char *setParamModes;

static void set(char **field, const char *value) {
	free(*field);
	*field = strdup(value);
	if (!*field) err(EX_OSERR, "strdup");
}

typedef void Handler(struct Message *msg);

static void handleCap(struct Message *msg) {
	require(msg, false, 3);
	if (strcmp(msg->params[2], "sasl")) return;
	if (!strcmp(msg->params[1], "ACK")) {
		format("AUTHENTICATE EXTERNAL\r\n");
	} else if (!strcmp(msg->params[1], "NAK")) {
		errx(EX_CONFIG, "server does not support SASL");
	}
}

static void handleAuthenticate(struct Message *msg) {
	(void)msg;
	format("AUTHENTICATE +\r\n");
}

static void handleReplyLoggedIn(struct Message *msg) {
	(void)msg;
	format("CAP END\r\n");
}

static void handleErrorSASLFail(struct Message *msg) {
	require(msg, false, 2);
	errx(EX_CONFIG, "%s", msg->params[1]);
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
		} else if (!strcmp(key, "STATUSMSG")) {
			set(&statusmsg, msg->params[i]);
		} else if (!strcmp(key, "PREFIX")) {
			strsep(&msg->params[i], "(");
			char *modes = strsep(&msg->params[i], ")");
			if (!modes || !msg->params[i]) {
				errx(EX_PROTOCOL, "invalid PREFIX value");
			}
			set(&prefixModes, modes);
			set(&prefixes, msg->params[i]);
		} else if (!strcmp(key, "CHANMODES")) {
			char *list = strsep(&msg->params[i], ",");
			char *param = strsep(&msg->params[i], ",");
			char *setParam = strsep(&msg->params[i], ",");
			if (!list || !param || !setParam) {
				errx(EX_PROTOCOL, "invalid CHANMODES value");
			}
			set(&listModes, list);
			set(&paramModes, param);
			set(&setParamModes, setParam);
		}
	}
}

static struct {
	char *buf;
	size_t cap, len;
} motd;

static void handleReplyMOTD(struct Message *msg) {
	require(msg, false, 2);
	char *line = msg->params[1];
	if (!strncmp(line, "- ", 2)) line += 2;
	size_t len = strlen(line);
	size_t req = motd.len + len + 1;
	if (req > motd.cap) {
		if (!motd.cap) motd.cap = 1024;
		while (req > motd.cap) motd.cap *= 2;
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
		VALUES (strftime('%s', coalesce(:time, 'now')), :network, :motd);
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

static char *scooperURL;

static void urlEncode(const char *str) {
	static const char *Safe = {
		"$-_.+!*'(),"
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
	};
	while (*str) {
		size_t len = strspn(str, Safe);
		if (len) clientWrite(str, len);
		str += len;
		if (*str == ' ') {
			clientWrite("+", 1);
			str++;
		} else if (*str) {
			format("%%%02X", *str++);
		}
	}
}

static int color(const char *user) {
	return 2 + hash(user) % 74;
}

static void querySearch(struct Message *msg) {
	static sqlite3_stmt *stmt;
	const char *sql = SQL(
		WITH results AS (
			SELECT
				contexts.name AS context,
				strftime('%Y-%m-%dT%H:%M:%SZ', events.time, 'unixepoch') AS time,
				events.type,
				names.nick,
				names.user,
				events.target,
				highlight(search, 6, :bold, :bold),
				events.event
			FROM events
			JOIN contexts USING (context)
			JOIN names USING (name)
			JOIN search ON search.rowid = events.event
			WHERE contexts.network = :network
				AND coalesce(contexts.query = :query, true)
				AND search MATCH :search
			ORDER BY search.rowid DESC
			LIMIT :limit
		)
		SELECT * FROM results
		ORDER BY time, event;
	);
	dbPersist(&stmt, sql);
	dbBindText(stmt, ":bold", "\2");
	dbBindInt(stmt, ":limit", searchLimit);

	dbBindText(stmt, ":network", network);
	if (searchQuery == Public) {
		dbBindInt(stmt, ":query", false);
	}
	dbBindText(stmt, ":search", msg->params[1]);

	int result;
	while (SQLITE_ROW == (result = sqlite3_step(stmt))) {
		int i = 0;
		const char *context = (const char *)sqlite3_column_text(stmt, i++);
		const char *time = (const char *)sqlite3_column_text(stmt, i++);
		enum Type type = sqlite3_column_int(stmt, i++);
		const char *nick = (const char *)sqlite3_column_text(stmt, i++);
		const char *user = (const char *)sqlite3_column_text(stmt, i++);
		const char *target = (const char *)sqlite3_column_text(stmt, i++);
		const char *message = (const char *)sqlite3_column_text(stmt, i++);
		if (!target) target = "";
		if (!message) message = "";
		if (!strcmp(user, "*")) user = nick;

		format(
			"NOTICE %s :\3%02d%s\3: [%s] ",
			msg->nick, color(context), context, time
		);
		switch (type) {
			break; case Privmsg:
				format("\3%d<%s>\3 %s\r\n", color(user), nick, message);
			break; case Notice:
				format("\3%d-%s-\3 %s\r\n", color(user), nick, message);
			break; case Action:
				format("\3%d* %s\3 %s\r\n", color(user), nick, message);
			break; case Join:
				format("\3%02d%s\3 joined\r\n", color(user), nick);
			break; case Part:
				format("\3%02d%s\3 parted: %s\r\n", color(user), nick, message);
			break; case Quit:
				format("\3%02d%s\3 quit: %s\r\n", color(user), nick, message);
			break; case Kick:
				format(
					"\3%02d%s\3 kicked %s: %s\r\n",
					color(user), nick, target, message
				);
			break; case Nick:
				format(
					"\3%02d%s\3 changed nick to \3%02d%s\3\r\n",
					color(user), nick, color(user), target
				);
			break; case Topic:
				format(
					"\3%02d%s\3 set the topic: %s\r\n",
					color(user), nick, message
				);
			break; case Ban:
				format("\3%02d%s\3 banned %s\r\n", color(user), nick, target);
			break; case Unban:
				format("\3%02d%s\3 unbanned %s\r\n", color(user), nick, target);
		}
	}
	if (result != SQLITE_DONE) {
		const char *errmsg = sqlite3_errmsg(db);
		if (!strncmp(errmsg, "fts5:", 5)) {
			format("NOTICE %s :%s\r\n", msg->nick, errmsg);
		} else {
			warnx("%s", sqlite3_errmsg(db));
		}
	} else if (scooperURL) {
		format("NOTICE %s :%s/search?network=", msg->nick, scooperURL);
		urlEncode(network);
		format("&query=");
		urlEncode(msg->params[1]);
		format("\r\n");
	}

	sqlite3_reset(stmt);
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
			strftime('%s', coalesce(:time, 'now')),
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

static enum Type messageType(struct Message *msg) {
	if (msg->cmd[0] == 'N') return Notice;
	if (strncmp(msg->params[1], "\1ACTION", 7)) return Privmsg;
	if (msg->params[1][7] == ' ') {
		msg->params[1] += 8;
	} else if (msg->params[1][7] == '\1') {
		msg->params[1] += 7;
	} else {
		return Privmsg;
	}
	size_t len = strlen(msg->params[1]);
	if (msg->params[1][len - 1] == '\1') {
		msg->params[1][len - 1] = '\0';
	}
	return Action;
}

static void handlePrivmsg(struct Message *msg) {
	require(msg, true, 2);

	bool query = true;
	const char *context = msg->params[0];
	if (statusmsg) context += strspn(context, statusmsg);
	if (strchr(chanTypes, context[0])) query = false;
	if (!strcmp(context, self)) context = msg->nick;
	enum Type type = messageType(msg);

	bool selfMessage = !strcmp(msg->nick, msg->params[0]);
	if (query && searchQuery && type == Privmsg) {
		if (searchQuery == Public || selfMessage) {
			querySearch(msg);
			return;
		}
	}
	if (selfMessage) return;

	insertContext(context, query);
	insertName(msg);
	insertEvent(msg, type, context, NULL, msg->params[1]);
}

static void insertTopic(
	const char *time, const char *context, const char *topic
) {
	static sqlite3_stmt *stmt;
	const char *sql = SQL(
		INSERT OR IGNORE INTO topics (time, context, topic)
		SELECT strftime('%s', coalesce(:time, 'now')), context, :topic
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
	for (char *names = msg->params[3]; names;) {
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
			strftime('%s', coalesce(:time, 'now')),
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

static void handleMode(struct Message *msg) {
	require(msg, true, 2);
	if (!strchr(chanTypes, msg->params[0][0])) return;
	insertContext(msg->params[0], false);
	insertName(msg);

	bool set = true;
	size_t param = 2;
	for (char *ch = msg->params[1]; *ch; ++ch) {
		if (*ch == '+') {
			set = true;
		} else if (*ch == '-') {
			set = false;
		} else if (*ch == 'b') {
			if (param >= ParamCap || !msg->params[param]) {
				errx(EX_PROTOCOL, "MODE missing ban target");
			}
			insertEvent(
				msg, (set ? Ban : Unban), msg->params[0],
				msg->params[param++], NULL
			);
		} else if (
			strchr(prefixModes, *ch) ||
			strchr(listModes, *ch) ||
			strchr(paramModes, *ch) ||
			(set && strchr(setParamModes, *ch))
		) {
			param++;
		}
	}
}

static void handlePing(struct Message *msg) {
	require(msg, false, 1);
	format("PONG :%s\r\n", msg->params[0]);
}

static void updateConsumer(size_t pos) {
	static sqlite3_stmt *stmt;
	const char *sql = SQL(
		INSERT INTO consumers (host, port, pos) VALUES (:host, :port, :pos)
		ON CONFLICT (host, port) DO
		UPDATE SET pos = :pos WHERE host = :host AND port = :port;
	);
	dbPersist(&stmt, sql);
	dbBindText(stmt, ":host", host);
	dbBindText(stmt, ":port", port);
	dbBindInt(stmt, ":pos", pos);
	dbRun(stmt);
}

static void handleError(struct Message *msg) {
	require(msg, false, 1);
	if (msg->pos) updateConsumer(msg->pos);
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
	{ "376", true, handleReplyEndOfMOTD },
	{ "900", false, handleReplyLoggedIn },
	{ "904", false, handleErrorSASLFail },
	{ "905", false, handleErrorSASLFail },
	{ "906", false, handleErrorSASLFail },
	{ "AUTHENTICATE", false, handleAuthenticate },
	{ "CAP", false, handleCap },
	{ "ERROR", false, handleError },
	{ "JOIN", true, handleJoin },
	{ "KICK", true, handleKick },
	{ "MODE", true, handleMode },
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

static void handle(struct Message *msg) {
	if (!msg->cmd) return;
	const struct Handler *handler = bsearch(
		msg->cmd, Handlers, ARRAY_LEN(Handlers), sizeof(*handler), compar
	);
	if (!handler) return;
	if (handler->transaction) {
		dbExec(SQL(BEGIN TRANSACTION;));
		handler->fn(msg);
		if (msg->pos) updateConsumer(msg->pos);
		dbExec(SQL(COMMIT TRANSACTION;));
	} else {
		handler->fn(msg);
	}
}

static void atExit(void) {
	dbExec(SQL(PRAGMA optimize;));
	dbClose();
	if (client) tls_close(client);
}

static void quit(int sig) {
	(void)sig;
	format("QUIT\r\n");
	atExit();
	_exit(EX_OK);
}

int main(int argc, char *argv[]) {
	bool init = false;
	bool migrate = false;
	const char *dbPath = NULL;
	const char *backup = NULL;

	bool insecure = false;
	const char *cert = NULL;
	const char *priv = NULL;
	const char *trust = NULL;
	const char *defaultNetwork = NULL;

	const char *nick = "litterbox";
	const char *user = NULL;
	const char *pass = NULL;

	struct option options[] = {
		{ .val = '!', .name = "insecure", no_argument },
		{ .val = 'N', .name = "network", required_argument },
		{ .val = 'Q', .name = "public-query", no_argument },
		{ .val = 'U', .name = "scooper-url", required_argument },
		{ .val = 'b', .name = "backup", required_argument },
		{ .val = 'c', .name = "cert", required_argument },
		{ .val = 'd', .name = "database", required_argument },
		{ .val = 'h', .name = "host", required_argument },
		{ .val = 'i', .name = "init", no_argument },
		{ .val = 'j', .name = "join", required_argument },
		{ .val = 'k', .name = "priv", required_argument },
		{ .val = 'l', .name = "limit", required_argument },
		{ .val = 'm', .name = "migrate", no_argument },
		{ .val = 'n', .name = "nick", required_argument },
		{ .val = 'p', .name = "port", required_argument },
		{ .val = 'q', .name = "private-query", no_argument },
		{ .val = 't', .name = "trust", required_argument },
		{ .val = 'u', .name = "user", required_argument },
		{ .val = 'v', .name = "verbose", no_argument },
		{ .val = 'w', .name = "pass", required_argument },
		{0},
	};
	char opts[2 * ARRAY_LEN(options)];
	for (size_t i = 0, j = 0; i < ARRAY_LEN(options); ++i) {
		opts[j++] = options[i].val;
		if (options[i].has_arg) opts[j++] = ':';
	}

	for (int opt; 0 < (opt = getopt_config(argc, argv, opts, options, NULL));) {
		switch (opt) {
			break; case '!': insecure = true;
			break; case 'N': defaultNetwork = optarg;
			break; case 'Q': searchQuery = Public;
			break; case 'U': scooperURL = optarg;
			break; case 'b': backup = optarg;
			break; case 'c': cert = optarg;
			break; case 'd': dbPath = optarg;
			break; case 'h': host = optarg;
			break; case 'i': init = true;
			break; case 'j': join = optarg;
			break; case 'k': priv = optarg;
			break; case 'l': searchLimit = strtol(optarg, NULL, 0);
			break; case 'm': migrate = true;
			break; case 'n': nick = optarg;
			break; case 'p': port = optarg;
			break; case 'q': searchQuery = Private;
			break; case 't': trust = optarg;
			break; case 'u': user = optarg;
			break; case 'v': verbose = true;
			break; case 'w': pass = optarg;
			break; default:  return EX_USAGE;
		}
	}
	if (!user) user = nick;
	if (scooperURL && scooperURL[0]) {
		size_t len = strlen(scooperURL);
		if (scooperURL[len - 1] == '/') scooperURL[len - 1] = '\0';
	}

	int flags = SQLITE_OPEN_READWRITE;
	if (init) flags |= SQLITE_OPEN_CREATE;
	dbFind(dbPath, flags);
	atexit(atExit);

	if (init) {
		dbInit();
		return EX_OK;
	}
	if (backup) {
		dbBackup(backup);
		return EX_OK;
	}
	dbMigrate();
	if (migrate) return EX_OK;
	createJoins();

	if (!host) errx(EX_USAGE, "host required");
	set(&self, "*");
	set(&network, (defaultNetwork ? defaultNetwork : host));
	set(&chanTypes, "#&");
	set(&prefixes, "@+");
	set(&prefixModes, "ov");
	set(&listModes, "b");
	set(&paramModes, "k");
	set(&setParamModes, "l");

	client = tls_client();
	if (!client) errx(EX_SOFTWARE, "tls_client");

	int error;
	char path[PATH_MAX];
	struct tls_config *config = tls_config_new();
	if (!config) errx(EX_SOFTWARE, "tls_config_new");

	if (insecure) {
		tls_config_insecure_noverifycert(config);
		tls_config_insecure_noverifyname(config);
	}
	if (trust) {
		tls_config_insecure_noverifyname(config);
		for (int i = 0; configPath(path, sizeof(path), trust, i); ++i) {
			error = tls_config_set_ca_file(config, path);
			if (!error) break;
		}
		if (error) errx(EX_NOINPUT, "%s: %s", trust, tls_config_error(config));
	}

	if (cert) {
		for (int i = 0; configPath(path, sizeof(path), cert, i); ++i) {
			if (priv) {
				error = tls_config_set_cert_file(config, path);
			} else {
				error = tls_config_set_keypair_file(config, path, path);
			}
			if (!error) break;
		}
		if (error) errx(EX_NOINPUT, "%s: %s", cert, tls_config_error(config));
	}
	if (priv) {
		for (int i = 0; configPath(path, sizeof(path), priv, i); ++i) {
			error = tls_config_set_key_file(config, path);
			if (!error) break;
		}
		if (error) errx(EX_NOINPUT, "%s: %s", priv, tls_config_error(config));
	}

	error = tls_configure(client, config);
	if (error) errx(EX_SOFTWARE, "tls_configure: %s", tls_error(client));
	tls_config_free(config);

	error = tls_connect(client, host, port);
	if (error) errx(EX_UNAVAILABLE, "tls_connect: %s", tls_error(client));

	size_t consumerPos = 0;
	sqlite3_stmt *stmt = dbPrepare(
		SQL(SELECT pos FROM consumers WHERE host = :host AND port = :port;)
	);
	dbBindText(stmt, ":host", host);
	dbBindText(stmt, ":port", port);
	if (dbStep(stmt) == SQLITE_ROW) {
		consumerPos = sqlite3_column_int64(stmt, 0);
	}
	sqlite3_finalize(stmt);

	if (pass) format("PASS :%s\r\n", pass);
	if (cert) format("CAP REQ :sasl\r\n");
	format("CAP REQ :server-time\r\n");
	format("CAP REQ :causal.agency/passive\r\n");
	if (consumerPos) {
		format("CAP REQ :causal.agency/consumer=%zu\r\n", consumerPos);
	} else {
		format("CAP REQ :causal.agency/consumer\r\n");
	}
	if (!cert) format("CAP END\r\n");
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
			struct Message msg = parse(line);
			handle(&msg);
			line = crlf + 2;
		}
		len -= line - buf;
		memmove(buf, line, len);
	}
}
