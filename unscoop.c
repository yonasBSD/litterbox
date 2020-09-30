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

enum { ParamCap = 8 };

struct Matcher {
	const char *pattern;
	enum Type type;
	const char *params[ParamCap];
};

#define P0_MODE "[!~&@%+ ]?"
#define P1_TIME "^[[]([^]]+)[]][ \t]"

static const struct Matcher Catgirl[] = {
	{
		P1_TIME "<([^>]+)> (.+)",
		Privmsg, { ":time", ":nick", ":message" },
	}, {
		P1_TIME "-([^-]+)- (.+)",
		Notice, { ":time", ":nick", ":message" },
	}, {
		P1_TIME "[*] ([^ ]+) (.+)",
		Action, { ":time", ":nick", ":message" },
	}, {
		P1_TIME "([^ ]+) arrives",
		Join, { ":time", ":nick" },
	}, {
		P1_TIME "([^ ]+) leaves [^:]+(: (.+))?",
		Part, { ":time", ":nick", NULL, ":message" },
	}, {
		P1_TIME "([^ ]+) kicks ([^ ]+) out of [^:]+(: (.+))?",
		Kick, { ":time", ":nick", ":target", NULL, ":message" },
	}, {
		P1_TIME "([^ ]+) leaves(: (.+))?",
		Quit, { ":time", ":nick", NULL, ":message" },
	}, {
		P1_TIME "([^ ]+) is now known as ([^ ]+)",
		Nick, { ":time", ":nick", ":target" },
	}, {
		P1_TIME "([^ ]+) places a new sign in [^:]+: (.+)",
		Topic, { ":time", ":nick", ":message" },
	}, {
		P1_TIME "([^ ]+) removes the sign in",
		Topic, { ":time", ":nick" },
	}, {
		P1_TIME "([^ ]+) bans [+]b ([^ ]+)",
		Ban, { ":time", ":nick", ":target" },
	}, {
		P1_TIME "([^ ]+) unbans [-]b ([^ ]+)",
		Unban, { ":time", ":nick", ":target" },
	}
};

static const struct Matcher Generic[] = {
	{
		P1_TIME "<" P0_MODE "([^>]+)>[ \t](.+)",
		Privmsg, { ":time", ":nick", ":message" },
	}, {
		P1_TIME "-" P0_MODE "([^-]+)-[ \t](.+)",
		Notice, { ":time", ":nick", ":message" },
	}, {
		P1_TIME "[*][ \t]" P0_MODE "([^ \t]+)[ \t](.+)",
		Action, { ":time", ":nick", ":message" },
	},
};

#define P2_TAGS "^@([^;]+;)*time=([^ ;]+)[^ ]* "
#define P3_ORIGIN ":([^!]+)!([^@]+)@([^ ]+) "
static const struct Matcher IRC[] = {
	{
		P2_TAGS P3_ORIGIN "PRIVMSG [^ ]+ :?\1ACTION ([^\1]+)",
		Action, { NULL, ":time", ":nick", ":user", ":host", ":message" },
	}, {
		P2_TAGS P3_ORIGIN "PRIVMSG [^ ]+ :?(.+)",
		Privmsg, { NULL, ":time", ":nick", ":user", ":host", ":message" },
	}, {
		P2_TAGS P3_ORIGIN "NOTICE [^ ]+ :?(.+)",
		Notice, { NULL, ":time", ":nick", ":user", ":host", ":message" },
	}, {
		P2_TAGS P3_ORIGIN "JOIN [^ ]+",
		Join, { NULL, ":time", ":nick", ":user", ":host" },
	}, {
		P2_TAGS P3_ORIGIN "PART [^ ]+( :?(.+))?",
		Part, { NULL, ":time", ":nick", ":user", ":host", NULL, ":message" },
	}, {
		P2_TAGS P3_ORIGIN "KICK [^ ]+ ([^ ]+)( :?(.+))?",
		Kick, {
			NULL, ":time", ":nick", ":user", ":host", ":target",
			NULL, ":message"
		},
	}, {
		P2_TAGS P3_ORIGIN "QUIT( :?(.+))?",
		Quit, { NULL, ":time", ":nick", ":user", ":host", NULL, ":message" },
	}, {
		P2_TAGS P3_ORIGIN "NICK :?([^ ]+)",
		Nick, { NULL, ":time", ":nick", ":user", ":host", ":target" },
	}, {
		P2_TAGS P3_ORIGIN "TOPIC [^ ]+( :?(.+))?",
		Topic, { NULL, ":time", ":nick", ":user", ":host", NULL, ":message" },
	}, {
		P2_TAGS P3_ORIGIN "MODE [^ ]+ [+]b+ :?(.+)",
		Ban, { NULL, ":time", ":nick", ":user", ":host", ":target" },
	}, {
		P2_TAGS P3_ORIGIN "MODE [^ ]+ [-]b+ :?(.+)",
		Unban, { NULL, ":time", ":nick", ":user", ":host", ":target" },
	},
};
#undef P2_TAGS
#undef P3_ORIGIN

#define P2_USERHOST "[(]([^@]+)@([^)]+)[)]"
#define P2_MESSAGE "( [(]([^)]+)[)])?"
static const struct Matcher Textual[] = {
	{
		P1_TIME "<" P0_MODE "([^>]+)> (.+)",
		Privmsg, { ":time", ":nick", ":message" },
	}, {
		P1_TIME "-" P0_MODE "([^-]+)- (.+)",
		Notice, { ":time", ":nick", ":message" },
	}, {
		P1_TIME "• ([^:]+): (.+)",
		Action, { ":time", ":nick", ":message" },
	}, {
		P1_TIME "([^ ]+) " P2_USERHOST " joined the channel",
		Join, { ":time", ":nick", ":user", ":host" },
	}, {
		P1_TIME "([^ ]+) " P2_USERHOST " left the channel" P2_MESSAGE,
		Part, { ":time", ":nick", ":user", ":host", NULL, ":message" },
	}, {
		P1_TIME "([^ ]+) kicked ([^ ]+) from the channel" P2_MESSAGE,
		Kick, { ":time", ":nick", ":target", NULL, ":message" },
	}, {
		P1_TIME "([^ ]+) " P2_USERHOST " left IRC" P2_MESSAGE,
		Quit, { ":time", ":nick", ":user", ":host", NULL, ":message" },
	}, {
		P1_TIME "([^ ]+) is now known as ([^ ]+)",
		Nick, { ":time", ":nick", ":target" },
	}, {
		P1_TIME "([^ ]+) changed the topic to (.+)",
		Topic, { ":time", ":nick", ":message" },
	}, {
		P1_TIME "([^ ]+) sets mode [+]b+ (.+)",
		Ban, { ":time", ":nick", ":target" },
	}, {
		P1_TIME "([^ ]+) sets mode [-]b+ (.+)",
		Unban, { ":time", ":nick", ":target" },
	}
};
#undef P2_USERHOST
#undef P2_MESSAGE

static const struct Format {
	const char *name;
	const struct Matcher *matchers;
	size_t len;
	const char *pattern;
	size_t network;
	size_t context;
} Formats[] = {
	{
		"generic", Generic, ARRAY_LEN(Generic),
		"([^/]+)/([^/]+)/[^/]+$", 1, 2,
	},
	{
		"catgirl", Catgirl, ARRAY_LEN(Catgirl),
		"([^/]+)/([^/]+)/[0-9-]+[.]log$", 1, 2,
	},
	{
		"irc", IRC, ARRAY_LEN(IRC),
		"^$", 0, 0,
	},
	{
		"textual", Textual, ARRAY_LEN(Textual),
		(
			"(([^ /]| [^(])+) [(][0-9A-F]+[)]/"
			"(Channels|Queries)/"
			"([^/]+)/"
			"[0-9-]+[.]txt$"
		),
		1, 4,
	},
};

static const struct Format *formatParse(const char *name) {
	for (size_t i = 0; i < ARRAY_LEN(Formats); ++i) {
		if (!strcmp(name, Formats[i].name)) return &Formats[i];
	}
	errx(EX_USAGE, "no such format %s", name);
}

static regex_t compile(const char *pattern) {
	regex_t regex;
	int error = regcomp(&regex, pattern, REG_EXTENDED | REG_NEWLINE);
	if (!error) return regex;
	char buf[256];
	regerror(error, &regex, buf, sizeof(buf));
	errx(EX_SOFTWARE, "regcomp: %s: %s", buf, pattern);
}

static void bindMatch(
	sqlite3_stmt *stmt, const char *param, const char *str, regmatch_t match
) {
	if (match.rm_so < 0) {
		dbBindNull(stmt, param);
	} else {
		dbBindTextLen(stmt, param, &str[match.rm_so], match.rm_eo - match.rm_so);
	}
}

static sqlite3_stmt *insertName;
static sqlite3_stmt *insertEvent;
static int paramNetwork;
static int paramContext;

static void prepareInsert(void) {
	const char *InsertName = SQL(
		INSERT OR IGNORE INTO names (nick, user, host)
		VALUES (:nick, coalesce(:user, '*'), coalesce(:host, '*'));
	);
	dbPersist(&insertName, InsertName);

	const char *InsertEvent = SQL(
		INSERT INTO events (time, type, context, name, target, message)
		SELECT
			// SQLite expects a colon in the timezine, but ISO8601 does not.
			CASE WHEN :time LIKE '%Z'
				THEN strftime('%s', :time)
				ELSE strftime('%s', substr(:time, 1, 22) || ':' || substr(:time, -2))
			END,
			:type, context, names.name, :target, :message
		FROM contexts, names
		WHERE contexts.network = :network
			AND contexts.name = :context
			AND names.nick = :nick
			AND names.user = coalesce(:user, '*')
			AND names.host = coalesce(:host, '*');
	);
	dbPersist(&insertEvent, InsertEvent);
	paramNetwork = dbParam(insertEvent, ":network");
	paramContext = dbParam(insertEvent, ":context");
}

static void
matchLine(const struct Format *format, const regex_t *regex, const char *line) {
	for (size_t i = 0; i < format->len; ++i) {
		const struct Matcher *matcher = &format->matchers[i];
		regmatch_t match[ParamCap];
		if (regexec(&regex[i], line, ParamCap, match, 0)) continue;

		sqlite3_clear_bindings(insertName);
		for (int i = 1; i <= sqlite3_bind_parameter_count(insertEvent); ++i) {
			if (i == paramNetwork || i == paramContext) continue;
			sqlite3_bind_null(insertEvent, i);
		}

		dbBindInt(insertEvent, ":type", matcher->type);
		for (size_t i = 0; i < ARRAY_LEN(matcher->params); ++i) {
			const char *param = matcher->params[i];
			if (!param) continue;
			if (sqlite3_bind_parameter_index(insertName, param)) {
				bindMatch(insertName, param, line, match[1 + i]);
			}
			bindMatch(insertEvent, param, line, match[1 + i]);
		}

		dbRun(insertName);
		dbRun(insertEvent);
		break;
	}
}

static void dedupEvents(sqlite3 *db) {
	if (sqlite3_libversion_number() < 3025000) {
		errx(EX_CONFIG, "SQLite version 3.25.0 or newer required");
	}
	const char *Delete = SQL(
		WITH potentials (event, diff) AS (
			SELECT event, event - first_value(event) OVER matching
			FROM events JOIN names USING (name)
			WINDOW matching AS (
				PARTITION BY time, type, context, nick, target, message
				ORDER BY event
			)
		), duplicates AS (SELECT event FROM potentials WHERE diff > 50)
		DELETE FROM events WHERE event IN duplicates;
	);
	dbExec(Delete);
	printf("deleted %d events\n", sqlite3_changes(db));
}

int main(int argc, char *argv[]) {
	bool test = false;
	bool dedup = false;
	const char *path = NULL;
	const char *network = NULL;
	const char *context = NULL;
	const struct Format *format = &Formats[0];

	for (int opt; 0 < (opt = getopt(argc, argv, "!DN:c:d:f:v"));) {
		switch (opt) {
			break; case '!': test = true;
			break; case 'D': dedup = true;
			break; case 'N': network = optarg;
			break; case 'c': context = optarg;
			break; case 'd': path = optarg;
			break; case 'f': format = formatParse(optarg);
			break; case 'v': verbose = true;
			break; default:  return EX_USAGE;
		}
	}

	regex_t pathRegex = compile(format->pattern);
	regex_t regex[format->len];
	for (size_t i = 0; i < format->len; ++i) {
		regex[i] = compile(format->matchers[i].pattern);
	}
	if (test) return EX_OK;

	dbFind(path, SQLITE_OPEN_READWRITE);
	if (dbVersion() != DatabaseVersion) {
		errx(EX_CONFIG, "database out of date; migrate with litterbox -m");
	}

	if (dedup) {
		dedupEvents(db);
		sqlite3_close(db);
		return EX_OK;
	}

	sqlite3_stmt *insertContext = NULL;
	const char *InsertContext = SQL(
		INSERT OR IGNORE INTO contexts (network, name, query)
		VALUES (
			:network, :context,
			NOT (:context LIKE '#%' OR :context LIKE '&%')
		);
	);
	dbPersist(&insertContext, InsertContext);
	dbBindText(insertContext, ":network", network);
	dbBindText(insertContext, ":context", context);

	prepareInsert();
	dbBindText(insertEvent, ":network", network);
	dbBindText(insertEvent, ":context", context);

	size_t sizeTotal = 0;
	size_t sizeRead = 0;
	size_t sizePercent = -1;
	regmatch_t match[argc][ParamCap];

	for (int i = optind; i < argc; ++i) {
		int error = regexec(&pathRegex, argv[i], ParamCap, match[i], 0);
		if (error && (!network || !context)) {
			warnx("skipping %s", argv[i]);
			argv[i] = NULL;
			continue;
		}
		struct stat st;
		error = stat(argv[i], &st);
		if (error) err(EX_NOINPUT, "%s", argv[i]);
		sizeTotal += st.st_size;
	}
	if (!sizeTotal) errx(EX_NOINPUT, "no input files");

	char *line = NULL;
	size_t cap = 0;
	for (int i = optind; i < argc; ++i) {
		if (!argv[i]) continue;

		FILE *file = fopen(argv[i], "r");
		if (!file) err(EX_NOINPUT, "%s", argv[i]);
		dbExec(SQL(BEGIN TRANSACTION;));

		regmatch_t pathNetwork = match[i][format->network];
		regmatch_t pathContext = match[i][format->context];
		if (!network) {
			bindMatch(insertContext, ":network", argv[i], pathNetwork);
			bindMatch(insertEvent, ":network", argv[i], pathNetwork);
		}
		if (!context) {
			bindMatch(insertContext, ":context", argv[i], pathContext);
			bindMatch(insertEvent, ":context", argv[i], pathContext);
		}
		dbRun(insertContext);

		for (ssize_t len; 0 < (len = getline(&line, &cap, file));) {
			matchLine(format, regex, line);
			sizeRead += len;
			if (100 * sizeRead / sizeTotal != sizePercent) {
				sizePercent = 100 * sizeRead / sizeTotal;
				printf("\r%3zu%%", sizePercent);
				fflush(stdout);
			}
		}
		if (ferror(file)) err(EX_IOERR, "%s", argv[i]);

		fclose(file);
		dbExec(SQL(COMMIT TRANSACTION;));
	}
	printf("\n");

	dbClose();
}
