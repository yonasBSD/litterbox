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
#include <regex.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <unistd.h>

#include "database.h"

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

struct Matcher {
	const char *pattern;
	regex_t regex;
	enum Type type;
	size_t time;
	size_t nick;
	size_t user;
	size_t host;
	size_t target;
	size_t message;
};

#define WS "[[:blank:]]"
#define P1_TIME "[[]([^]]+)[]]"
#define P0_MODE "[!~&@%+ ]?"

static struct Matcher Generic[] = {
	{
		"^" P1_TIME WS "<" P0_MODE "([^>]+)" ">" WS "(.+)",
		.type = Privmsg, .time = 1, .nick = 2, .message = 3,
	},
	{
		"^" P1_TIME WS "-" P0_MODE "([^-]+)" "-" WS "(.+)",
		.type = Notice, .time = 1, .nick = 2, .message = 3,
	},
	{
		"^" P1_TIME WS "[*]" WS P0_MODE "([^[:blank:]]+)" WS "(.+)",
		.type = Action, .time = 1, .nick = 2, .message = 3,
	},
};

#define P2_USERHOST "[(]([^@]+)@([^)]+)[)]"
#define P2_MESSAGE "( [(]([^)]+)[)])?"
static struct Matcher Textual[] = {
	{
		"^" P1_TIME " <" P0_MODE "([^>]+)> (.+)",
		.type = Privmsg, .time = 1, .nick = 2, .message = 3,
	},
	{
		"^" P1_TIME " -" P0_MODE "([^-]+)- (.+)",
		.type = Notice, .time = 1, .nick = 2, .message = 3,
	},
	{
		"^" P1_TIME " • ([^:]+): (.+)",
		.type = Action, .time = 1, .nick = 2, .message = 3,
	},
	{
		"^" P1_TIME " ([^ ]+) " P2_USERHOST " joined the channel",
		.type = Join, .time = 1, .nick = 2, .user = 3, .host = 4,
	},
	{
		"^" P1_TIME " ([^ ]+) " P2_USERHOST " left the channel" P2_MESSAGE,
		.type = Part, .time = 1, .nick = 2, .user = 3, .host = 4, .message = 6,
	},
	{
		"^" P1_TIME " ([^ ]+) kicked ([^ ]+) from the channel" P2_MESSAGE,
		.type = Kick, .time = 1, .nick = 2, .target = 3, .message = 5,
	},
	{
		"^" P1_TIME " ([^ ]+) " P2_USERHOST " left IRC" P2_MESSAGE,
		.type = Quit, .time = 1, .nick = 2, .user = 3, .host = 4, .message = 6,
	},
	{
		"^" P1_TIME " ([^ ]+) is now known as ([^ ]+)",
		.type = Nick, .time = 1, .nick = 2, .target = 3,
	},
	{
		"^" P1_TIME " ([^ ]+) changed the topic to (.+)",
		.type = Topic, .time = 1, .nick = 2, .message = 3,
	},
};

#undef P2_MESSAGE
#define P2_MESSAGE "(, \"([^\"]+)\")?"
static struct Matcher Catgirl[] = {
	{
		"^" P1_TIME " <([^>]+)> (.+)",
		.type = Privmsg, .time = 1, .nick = 2, .message = 3,
	},
	{
		"^" P1_TIME " -([^-]+)- (.+)",
		.type = Notice, .time = 1, .nick = 2, .message = 3,
	},
	{
		"^" P1_TIME " [*] ([^ ]+) (.+)",
		.type = Action, .time = 1, .nick = 2, .message = 3,
	},
	{
		"^" P1_TIME " ([^ ]+) arrives",
		.type = Join, .time = 1, .nick = 2,
	},
	{
		"^" P1_TIME " ([^ ]+) leaves [^,]+" P2_MESSAGE,
		.type = Part, .time = 1, .nick = 2, .message = 4,
	},
	{
		"^" P1_TIME " ([^ ]+) kicks ([^ ]+) out of [^,]+" P2_MESSAGE,
		.type = Kick, .time = 1, .nick = 2, .target = 3, .message = 5,
	},
	{
		"^" P1_TIME " ([^ ]+) leaves" P2_MESSAGE,
		.type = Quit, .time = 1, .nick = 2, .message = 4,
	},
	{
		"^" P1_TIME " ([^ ]+) is now known as ([^ ]+)",
		.type = Nick, .time = 1, .nick = 2, .target = 3,
	},
	{
		"^" P1_TIME " ([^ ]+) places a new sign in [^,]+" P2_MESSAGE,
		.type = Topic, .time = 1, .nick = 2, .message = 3,
	},
};

static const struct Format {
	const char *name;
	struct Matcher *matchers;
	size_t len;
} Formats[] = {
	{ "generic", Generic, ARRAY_LEN(Generic) },
	{ "textual", Textual, ARRAY_LEN(Textual) },
	{ "catgirl", Catgirl, ARRAY_LEN(Catgirl) },
};

static const struct Format *formatParse(const char *name) {
	for (size_t i = 0; i < ARRAY_LEN(Formats); ++i) {
		if (!strcmp(name, Formats[i].name)) return &Formats[i];
	}
	errx(EX_USAGE, "no such format %s", name);
}

static void
bindMatch(sqlite3_stmt *stmt, int param, const char *str, regmatch_t match) {
	if (match.rm_so < 0) {
		dbBindText(stmt, param, NULL, -1);
	} else {
		dbBindText(stmt, param, &str[match.rm_so], match.rm_eo - match.rm_so);
	}
}

int main(int argc, char *argv[]) {
	char *path = NULL;
	bool dedup = false;
	const char *network = NULL;
	const char *context = NULL;
	const struct Format *format = &Formats[0];

	int opt;
	while (0 < (opt = getopt(argc, argv, "C:DN:d:f:"))) {
		switch (opt) {
			break; case 'C': context = optarg;
			break; case 'D': dedup = true;
			break; case 'N': network = optarg;
			break; case 'd': path = optarg;
			break; case 'f': format = formatParse(optarg);
			break; default:  return EX_USAGE;
		}
	}
	if (!dedup && !network) errx(EX_USAGE, "network required");
	if (!dedup && !context) errx(EX_USAGE, "context required");

	int flags = SQLITE_OPEN_READWRITE;
	sqlite3 *db = (path ? dbOpen(path, flags) : dbFind(flags));
	if (!db) errx(EX_NOINPUT, "database not found");

	if (dbVersion(db) != DatabaseVersion) {
		errx(EX_CONFIG, "database needs migration");
	}

	if (dedup) {
		if (sqlite3_libversion_number() < 3025000) {
			errx(EX_CONFIG, "SQLite version 3.25.0 or newer required");
		}
		int error = sqlite3_exec(
			db,
			"WITH potentials AS ("
			" SELECT event, event - first_value(event) OVER ("
			"  PARTITION BY time, type, context, nick, target, message"
			"  ORDER BY event"
			" ) AS diff"
			" FROM events JOIN names USING (name)"
			"), duplicates AS (SELECT event FROM potentials WHERE diff > 50)"
			"DELETE FROM events WHERE event IN duplicates;",
			NULL, NULL, NULL
		);
		if (error) {
			errx(EX_SOFTWARE, "sqlite3_exec: %s", sqlite3_errmsg(db));
		}
		printf("deleted %d events\n", sqlite3_changes(db));
		return EX_OK;
	}

	for (size_t i = 0; i < format->len; ++i) {
		struct Matcher *matcher = &format->matchers[i];
		int error = regcomp(
			&matcher->regex, matcher->pattern, REG_EXTENDED | REG_NEWLINE
		);
		if (!error) continue;
		char buf[256];
		regerror(error, &matcher->regex, buf, sizeof(buf));
		errx(EX_SOFTWARE, "regcomp: %s: %s", buf, matcher->pattern);
	}

	sqlite3_stmt *insertNetwork = dbPrepare(
		db, 0, "INSERT OR IGNORE INTO networks (name) VALUES ($network);"
	);
	dbBindText(insertNetwork, 1, network, -1);
	dbStep(insertNetwork);
	sqlite3_finalize(insertNetwork);

	sqlite3_stmt *insertContext = dbPrepare(
		db, 0,
		"INSERT OR IGNORE INTO contexts (network, name, query)"
		"SELECT network, $context, $query FROM networks WHERE name = $network;"
	);
	dbBindText(insertContext, 1, context, -1);
	dbBindInt(insertContext, 2, context[0] != '#' && context[0] != '&');
	dbBindText(insertContext, 3, network, -1);
	dbStep(insertContext);
	sqlite3_finalize(insertContext);

	int64_t contextID;
	sqlite3_stmt *selectContext = dbPrepare(
		db, 0,
		"SELECT context FROM contexts"
		" JOIN networks USING (network)"
		" WHERE networks.name = $network AND contexts.name = $context;"
	);
	dbBindText(selectContext, 1, network, -1);
	dbBindText(selectContext, 2, context, -1);
	assert(SQLITE_ROW == dbStep(selectContext));
	contextID = sqlite3_column_int64(selectContext, 0);
	sqlite3_finalize(selectContext);

	sqlite3_stmt *insertName = dbPrepare(
		db, SQLITE_PREPARE_PERSISTENT,
		"INSERT OR IGNORE INTO names (nick, user, host)"
		"VALUES ($nick, $user, $host);"
	);
	// SQLite expects a colon in the timezone, but ISO8601 does not.
	sqlite3_stmt *insertEvent = dbPrepare(
		db, SQLITE_PREPARE_PERSISTENT,
		"INSERT INTO events (context, type, time, name, target, message)"
		"SELECT"
		" $context, $type,"
		" datetime(substr($time, 1, 22) || ':' || substr($time, -2)),"
		" name, $target, $message"
		" FROM names WHERE nick = $nick AND user = $user AND host = $host;"
	);
	dbBindInt(insertEvent, 1, contextID);

	size_t sizeTotal = 0;
	for (int i = optind; i < argc; ++i) {
		struct stat st;
		int error = stat(argv[i], &st);
		if (error) err(EX_NOINPUT, "%s", argv[i]);
		sizeTotal += st.st_size;
	}

	size_t sizeRead = 0;
	size_t sizePercent = 101;

	char *line = NULL;
	size_t cap = 0;
	for (int i = optind; i < argc; ++i) {
		FILE *file = fopen(argv[i], "r");
		if (!file) err(EX_NOINPUT, "%s", argv[i]);

		dbBegin(db);
		ssize_t len;
		while (0 < (len = getline(&line, &cap, file))) {
			for (size_t i = 0; i < format->len; ++i) {
				const struct Matcher *matcher = &format->matchers[i];
				regmatch_t match[8];
				int error = regexec(
					&matcher->regex, line, ARRAY_LEN(match), match, 0
				);
				if (error) continue;

				dbBindInt(insertEvent, 2, matcher->type);
				bindMatch(insertEvent, 3, line, match[matcher->time]);
				if (matcher->target) {
					bindMatch(insertEvent, 4, line, match[matcher->target]);
				} else {
					dbBindText(insertEvent, 4, NULL, -1);
				}
				if (matcher->message) {
					bindMatch(insertEvent, 5, line, match[matcher->message]);
				} else {
					dbBindText(insertEvent, 5, NULL, -1);
				}
				bindMatch(insertEvent, 6, line, match[matcher->nick]);
				bindMatch(insertName, 1, line, match[matcher->nick]);
				if (matcher->user) {
					bindMatch(insertEvent, 7, line, match[matcher->user]);
					bindMatch(insertName, 2, line, match[matcher->user]);
				} else {
					dbBindText(insertEvent, 7, "*", -1);
					dbBindText(insertName, 2, "*", -1);
				}
				if (matcher->host) {
					bindMatch(insertEvent, 8, line, match[matcher->host]);
					bindMatch(insertName, 3, line, match[matcher->host]);
				} else {
					dbBindText(insertEvent, 8, "*", -1);
					dbBindText(insertName, 3, "*", -1);
				}

				dbStep(insertName);
				dbStep(insertEvent);
				sqlite3_reset(insertName);
				sqlite3_reset(insertEvent);
			}

			sizeRead += len;
			if (100 * sizeRead / sizeTotal != sizePercent) {
				sizePercent = 100 * sizeRead / sizeTotal;
				printf("\r%s/%s: %3zu%%", network, context, sizePercent);
				fflush(stdout);
			}
		}
		if (ferror(file)) err(EX_IOERR, "%s", argv[i]);
		fclose(file);
		dbCommit(db);
	}
	printf("\n");

	sqlite3_finalize(insertName);
	sqlite3_finalize(insertEvent);
	sqlite3_close(db);
}
