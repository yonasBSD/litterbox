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

enum { ParamCap = 8 };

struct Matcher {
	const char *pattern;
	enum Type type;
	const char *params[ParamCap];
};

#define P0_MODE "[!~&@%+ ]?"
#define P1_TIME "^[[]([^]]+)[]][ \t]"

#define P2_MESSAGE "(, \"([^\"]+)\")?"
static const struct Matcher Catgirl[] = {
	{
		P1_TIME "<([^>]+)> (.+)",
		Privmsg, { "$time", "$nick", "$message" },
	},
	{
		P1_TIME "-([^-]+)- (.+)",
		Notice, { "$time", "$nick", "$message" },
	},
	{
		P1_TIME "[*] ([^ ]+) (.+)",
		Action, { "$time", "$nick", "$message" },
	},
	{
		P1_TIME "([^ ]+) arrives",
		Join, { "$time", "$nick" },
	},
	{
		P1_TIME "([^ ]+) leaves [^,]+" P2_MESSAGE,
		Part, { "$time", "$nick", NULL, "$message" },
	},
	{
		P1_TIME "([^ ]+) kicks ([^ ]+) out of [^,]+" P2_MESSAGE,
		Kick, { "$time", "$nick", "$target", NULL, "$message" },
	},
	{
		P1_TIME "([^ ]+) leaves" P2_MESSAGE,
		Quit, { "$time", "$nick", NULL, "$message" },
	},
	{
		P1_TIME "([^ ]+) is now known as ([^ ]+)",
		Nick, { "$time", "$nick", "$target" },
	},
	{
		P1_TIME "([^ ]+) places a new sign in [^,]+" P2_MESSAGE,
		Topic, { "$time", "$nick", "$message" },
	},
};
#undef P2_MESSAGE

static const struct Matcher Generic[] = {
	{
		P1_TIME "<" P0_MODE "([^>]+)>[ \t](.+)",
		Privmsg, { "$time", "$nick", "$message" },
	},
	{
		P1_TIME "-" P0_MODE "([^-]+)-[ \t](.+)",
		Notice, { "$time", "$nick", "$message" },
	},
	{
		P1_TIME "[*][ \t]" P0_MODE "([^ \t]+)[ \t](.+)",
		Action, { "$time", "$nick", "$message" },
	},
};

#define P2_TAGS "^@([^;]+;)*time=([^ ;]+)[^ ]* "
#define P3_ORIGIN ":([^!]+)!([^@]+)@([^ ]+) "
static const struct Matcher IRC[] = {
	{
		P2_TAGS P3_ORIGIN "PRIVMSG [^ ]+ :?\1ACTION ([^\1]+)",
		Action, { NULL, "$time", "$nick", "$user", "$host", "$message" },
	},
	{
		P2_TAGS P3_ORIGIN "PRIVMSG [^ ]+ :?(.+)",
		Privmsg, { NULL, "$time", "$nick", "$user", "$host", "$message" },
	},
	{
		P2_TAGS P3_ORIGIN "NOTICE [^ ]+ :?(.+)",
		Notice, { NULL, "$time", "$nick", "$user", "$host", "$message" },
	},
	{
		P2_TAGS P3_ORIGIN "JOIN [^ ]+",
		Join, { NULL, "$time", "$nick", "$user", "$host" },
	},
	{
		P2_TAGS P3_ORIGIN "PART [^ ]+ :?(.+)?",
		Part, { NULL, "$time", "$nick", "$user", "$host", "$message" },
	},
	{
		P2_TAGS P3_ORIGIN "KICK [^ ]+ ([^ ]+) :?(.+)?",
		Kick,
		{ NULL, "$time", "$nick", "$user", "$host", "$target", "$message" },
	},
	{
		P2_TAGS P3_ORIGIN "QUIT( :?(.+))?",
		Quit, { NULL, "$time", "$nick", "$user", "$host", NULL, "$message" },
	},
	{
		P2_TAGS P3_ORIGIN "NICK :?([^ ]+)",
		Nick, { NULL, "$time", "$nick", "$user", "$host", "$target" },
	},
	{
		P2_TAGS P3_ORIGIN "TOPIC [^ ]+ :?(.+)",
		Topic, { NULL, "$time", "$nick", "$user", "$host", "$message" },
	},
};
#undef P2_TAGS
#undef P3_ORIGIN

#define P2_USERHOST "[(]([^@]+)@([^)]+)[)]"
#define P2_MESSAGE "( [(]([^)]+)[)])?"
static const struct Matcher Textual[] = {
	{
		P1_TIME "<" P0_MODE "([^>]+)> (.+)",
		Privmsg, { "$time", "$nick", "$message" },
	},
	{
		P1_TIME "-" P0_MODE "([^-]+)- (.+)",
		Notice, { "$time", "$nick", "$message" },
	},
	{
		P1_TIME "• ([^:]+): (.+)",
		Action, { "$time", "$nick", "$message" },
	},
	{
		P1_TIME "([^ ]+) " P2_USERHOST " joined the channel",
		Join, { "$time", "$nick", "$user", "$host" },
	},
	{
		P1_TIME "([^ ]+) " P2_USERHOST " left the channel" P2_MESSAGE,
		Part, { "$time", "$nick", "$user", "$host", NULL, "$message" },
	},
	{
		P1_TIME "([^ ]+) kicked ([^ ]+) from the channel" P2_MESSAGE,
		Kick, { "$time", "$nick", "$target", NULL, "$message" },
	},
	{
		P1_TIME "([^ ]+) " P2_USERHOST " left IRC" P2_MESSAGE,
		Quit, { "$time", "$nick", "$user", "$host", NULL, "$message" },
	},
	{
		P1_TIME "([^ ]+) is now known as ([^ ]+)",
		Nick, { "$time", "$nick", "$target" },
	},
	{
		P1_TIME "([^ ]+) changed the topic to (.+)",
		Topic, { "$time", "$nick", "$message" },
	},
};
#undef P2_USERHOST
#undef P2_MESSAGE

static const struct Format {
	const char *name;
	const struct Matcher *matchers;
	size_t len;
} Formats[] = {
	{ "generic", Generic, ARRAY_LEN(Generic) },

	{ "catgirl", Catgirl, ARRAY_LEN(Catgirl) },
	{ "irc", IRC, ARRAY_LEN(IRC) },
	{ "textual", Textual, ARRAY_LEN(Textual) },
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

static sqlite3_stmt *insertName;
static sqlite3_stmt *insertEvent;

static void prepareInsert(sqlite3 *db) {
	insertName = dbPrepare(
		db, SQLITE_PREPARE_PERSISTENT,
		"INSERT OR IGNORE INTO names (nick, user, host)"
		"VALUES ($nick, coalesce($user, '*'), coalesce($host, '*'));"
	);

	// SQLite expects a colon in the timezone, but ISO8601 does not.
	insertEvent = dbPrepare(
		db, SQLITE_PREPARE_PERSISTENT,
		"INSERT INTO events (context, type, time, name, target, message)"
		"SELECT"
		" $context, $type,"
		" CASE"
		"  WHEN $time LIKE '%Z' THEN datetime($time)"
		"  ELSE datetime(substr($time, 1, 22) || ':' || substr($time, -2))"
		" END,"
		" name, $target, $message"
		" FROM names"
		" WHERE nick = $nick"
		" AND user = coalesce($user, '*')"
		" AND host = coalesce($host, '*');"
	);
}

static void matchLine(
	int64_t context, const struct Format *format,
	const regex_t *regex, const char *line
) {
	for (size_t i = 0; i < format->len; ++i) {
		const struct Matcher *matcher = &format->matchers[i];
		regmatch_t match[ParamCap];
		int error = regexec(&regex[i], line, ParamCap, match, 0);
		if (error) continue;

		sqlite3_reset(insertName);
		sqlite3_reset(insertEvent);
		sqlite3_clear_bindings(insertName);
		sqlite3_clear_bindings(insertEvent);

		dbBindInt(insertEvent, 1, context);
		dbBindInt(insertEvent, 2, matcher->type);

		for (size_t i = 0; i < ARRAY_LEN(matcher->params); ++i) {
			const char *param = matcher->params[i];
			if (!param) continue;
			int p = sqlite3_bind_parameter_index(insertName, param);
			if (p) bindMatch(insertName, p, line, match[1 + i]);
			p = sqlite3_bind_parameter_index(insertEvent, param);
			if (!p) errx(EX_SOFTWARE, "no such parameter %s", param);
			bindMatch(insertEvent, p, line, match[1 + i]);
		}

		dbStep(insertName);
		dbStep(insertEvent);
		break;
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

	regex_t regex[format->len];
	for (size_t i = 0; i < format->len; ++i) {
		const struct Matcher *matcher = &format->matchers[i];
		int error = regcomp(
			&regex[i], matcher->pattern, REG_EXTENDED | REG_NEWLINE
		);
		if (!error) continue;
		char buf[256];
		regerror(error, &regex[i], buf, sizeof(buf));
		errx(EX_SOFTWARE, "regcomp: %s: %s", buf, matcher->pattern);
	}

	sqlite3_stmt *insertContext = dbPrepare(
		db, 0,
		"INSERT OR IGNORE INTO contexts (network, name, query)"
		"VALUES ($network, $context, $query);"
	);
	dbBindText(insertContext, 1, network, -1);
	dbBindText(insertContext, 2, context, -1);
	dbBindInt(insertContext, 3, context[0] != '#' && context[0] != '&');
	dbStep(insertContext);
	sqlite3_finalize(insertContext);

	sqlite3_stmt *selectContext = dbPrepare(
		db, 0,
		"SELECT context FROM contexts"
		" WHERE network = $network AND name = $context;"
	);
	dbBindText(selectContext, 1, network, -1);
	dbBindText(selectContext, 2, context, -1);
	assert(SQLITE_ROW == dbStep(selectContext));
	int64_t id = sqlite3_column_int64(selectContext, 0);
	sqlite3_finalize(selectContext);

	prepareInsert(db);

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
			matchLine(id, format, regex, line);
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
