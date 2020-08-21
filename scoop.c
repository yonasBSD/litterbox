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

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <regex.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <unistd.h>

#include "database.h"

// Look I never asked for select(2) to be declared.
#define select select_

#ifndef SQLITE3_BIN
#define SQLITE3_BIN "sqlite3"
#endif

struct Event {
	const char *network;
	const char *context;
	const char *time;
	enum Type type;
	const char *nick;
	const char *user;
	const char *host;
	const char *target;
	const char *message;
};

typedef void Format(bool group, struct Event event);

static void formatPlain(bool group, struct Event e) {
	(void)group;
	printf("%s/%s: [%s] ", e.network, e.context, e.time);
	switch (e.type) {
		break; case Privmsg: {
			printf("<%s> %s\n", e.nick, e.message);
		}
		break; case Notice: {
			printf("-%s- %s\n", e.nick, e.message);
		}
		break; case Action: {
			printf("* %s %s\n", e.nick, e.message);
		}
		break; case Join: {
			printf("%s joined\n", e.nick);
		}
		break; case Part: {
			printf("%s parted: %s\n", e.nick, e.message);
		}
		break; case Quit: {
			printf("%s quit: %s\n", e.nick, e.message);
		}
		break; case Kick: {
			printf("%s kicked %s: %s\n", e.nick, e.target, e.message);
		}
		break; case Nick: {
			printf("%s changed nick to %s\n", e.nick, e.target);
		}
		break; case Topic: {
			printf("%s set the topic: %s\n", e.nick, e.message);
		}
		break; case Ban: {
			printf("%s banned %s\n", e.nick, e.target);
		}
		break; case Unban: {
			printf("%s unbanned %s\n", e.nick, e.target);
		}
	}
}

static const int Colors[] = {
	31, 32, 33, 34, 35, 36, 37,
	90, 91, 92, 93, 94, 95, 96, 97,
};

static int color(const char *user) {
	return Colors[hash(user) % ARRAY_LEN(Colors)];
}

static const int ANSI[100] = {
	97, 30, 34, 32, 91, 31, 35, 33,
	93, 92, 36, 96, 94, 95, 90, 37,
};

static const char *ansi(const char *str) {
	static char buf[1024];
	FILE *out = fmemopen(buf, sizeof(buf), "w");
	if (!out) err(EX_OSERR, "fmemopen");

	int b = 0, i = 0, u = 0, r = 0;
	for (;;) {
		size_t len = strcspn(str, "\2\3\17\26\35\37");
		fprintf(out, "%.*s", (int)len, str);
		if (!str[len]) break;
		str += len;
		switch (*str++) {
			break; case '\2':  fprintf(out, "\33[%dm", ((b ^= 1) ? 1 : 22));
			break; case '\26': fprintf(out, "\33[%dm", ((r ^= 1) ? 7 : 27));
			break; case '\35': fprintf(out, "\33[%dm", ((i ^= 1) ? 3 : 23));
			break; case '\37': fprintf(out, "\33[%dm", ((u ^= 1) ? 4 : 24));
			break; case '\17': fprintf(out, "\33[m"); b = i = u = r = 0;
			break; case '\3': {
				if (!isdigit(*str)) {
					fprintf(out, "\33[39;49m");
					break;
				}
				int fg = *str++ - '0';
				if (isdigit(*str)) fg = fg * 10 + *str++ - '0';
				fprintf(out, "\33[%dm", (ANSI[fg] ? ANSI[fg] : 39));
				if (str[0] != ',' || !isdigit(str[1])) break;
				str++;
				int bg = *str++ - '0';
				if (isdigit(*str)) bg = bg * 10 + *str++ - '0';
				fprintf(out, "\33[%dm", (ANSI[bg] ? 10 + ANSI[bg] : 49));
			}
		}
	}
	fprintf(out, "\33[m");
	fclose(out);

	buf[sizeof(buf) - 1] = '\0';
	return buf;
}

static void formatColor(bool group, struct Event e) {
	static char network[256];
	static char context[256];
	if (group && (strcmp(e.network, network) || strcmp(e.context, context))) {
		printf("%s%s/%s:\n", (network[0] ? "\n" : ""), e.network, e.context);
		snprintf(network, sizeof(network), "%s", e.network);
		snprintf(context, sizeof(context), "%s", e.context);
	} else if (!group) {
		printf("%s/%s: ", e.network, e.context);
	}
	printf("[%s] ", e.time);

#define C(x) "\33[%dm" x "\33[m"
	switch (e.type) {
		break; case Privmsg: {
			printf(C("<%s>") " %s\n", color(e.user), e.nick, ansi(e.message));
		}
		break; case Notice: {
			printf(C("-%s-") " %s\n", color(e.user), e.nick, ansi(e.message));
		}
		break; case Action: {
			printf(C("* %s") " %s\n", color(e.user), e.nick, ansi(e.message));
		}
		break; case Join: {
			printf(C("%s") " joined\n", color(e.user), e.nick);
		}
		break; case Part: {
			printf(
				C("%s") " parted: %s\n", color(e.user), e.nick, ansi(e.message)
			);
		}
		break; case Quit: {
			printf(
				C("%s") " quit: %s\n", color(e.user), e.nick, ansi(e.message)
			);
		}
		break; case Kick: {
			printf(
				C("%s") " kicked %s: %s\n",
				color(e.user), e.nick, e.target, ansi(e.message)
			);
		}
		break; case Nick: {
			printf(
				C("%s") " changed nick to " C("%s") "\n",
				color(e.user), e.nick, color(e.user), e.target
			);
		}
		break; case Topic: {
			printf(
				C("%s") " set the topic: %s\n",
				color(e.user), e.nick, ansi(e.message)
			);
		}
		break; case Ban: {
			printf(C("%s") " banned %s\n", color(e.user), e.nick, e.target);
		}
		break; case Unban: {
			printf(C("%s") " unbanned %s\n", color(e.user), e.nick, e.target);
		}
	}
#undef C
}

static void formatIRC(bool group, struct Event e) {
	(void)group;
	if (!strcmp(e.host, e.nick)) {
		printf("@time=%s :%s ", e.time, e.host);
	} else {
		printf("@time=%s :%s!%s@%s ", e.time, e.nick, e.user, e.host);
	}
	if (!strcmp(e.context, e.nick)) e.context = "*";
	switch (e.type) {
		break; case Privmsg: {
			printf("PRIVMSG %s :%s\r\n", e.context, e.message);
		}
		break; case Notice: {
			printf("NOTICE %s :%s\r\n", e.context, e.message);
		}
		break; case Action: {
			printf("PRIVMSG %s :\1ACTION %s\1\r\n", e.context, e.message);
		}
		break; case Join: {
			printf("JOIN %s\r\n", e.context);
		}
		break; case Part: {
			printf("PART %s :%s\r\n", e.context, e.message);
		}
		break; case Quit: {
			printf("QUIT :%s\r\n", e.message);
		}
		break; case Kick: {
			printf("KICK %s %s :%s\r\n", e.context, e.target, e.message);
		}
		break; case Nick: {
			printf("NICK %s\r\n", e.target);
		}
		break; case Topic: {
			printf("TOPIC %s :%s\r\n", e.context, e.message);
		}
		break; case Ban: {
			printf("MODE %s +b %s\r\n", e.context, e.target);
		}
		break; case Unban: {
			printf("MODE %s -b %s\r\n", e.context, e.target);
		}
	}
}

static const struct {
	const char *name;
	Format *fn;
} Formats[] = {
	{ "plain", formatPlain },
	{ "color", formatColor },
	{ "irc", formatIRC },
};

static Format *parseFormat(const char *name) {
	for (size_t i = 0; i < ARRAY_LEN(Formats); ++i) {
		if (!strcmp(name, Formats[i].name)) return Formats[i].fn;
	}
	errx(EX_USAGE, "no such format %s", name);
}

static void regexpFree(void *_regex) {
	regex_t *regex = _regex;
	regfree(regex);
	free(regex);
}

static void regexp(sqlite3_context *ctx, int n, sqlite3_value *args[]) {
	assert(n == 2);
	if (sqlite3_value_type(args[0]) == SQLITE_NULL) {
		sqlite3_result_null(ctx);
		return;
	}
	if (sqlite3_value_type(args[1]) == SQLITE_NULL) {
		sqlite3_result_int(ctx, false);
		return;
	}

	regex_t *regex = sqlite3_get_auxdata(ctx, 0);
	if (!regex) {
		regex = malloc(sizeof(*regex));
		if (!regex) {
			sqlite3_result_error_nomem(ctx);
			return;
		}
		sqlite3_set_auxdata(ctx, 0, regex, regexpFree);

		int error = regcomp(
			regex, (const char *)sqlite3_value_text(args[0]),
			REG_EXTENDED | REG_NOSUB
		);
		if (error) {
			char msg[256];
			regerror(error, regex, msg, sizeof(msg));
			sqlite3_result_error(ctx, msg, -1);
			return;
		}
	}

	int error = regexec(
		regex, (const char *)sqlite3_value_text(args[1]), 0, NULL, 0
	);
	sqlite3_result_int(ctx, !error);
}

static char select[4096] = SQL(
	SELECT
		events.event,
		contexts.network,
		contexts.name AS context,
		CASE WHEN :local THEN
			strftime(
				coalesce(:format, '%Y-%m-%dT%H:%M:%S'),
				events.time, 'unixepoch', 'localtime'
			)
		ELSE
			strftime(
				coalesce(:format, '%Y-%m-%dT%H:%M:%SZ'),
				events.time, 'unixepoch'
			)
		END AS time,
		events.type,
		names.nick,
		names.user,
		names.host,
		events.target,
);

enum { QueryCap = 4096 };

static char from[QueryCap] = SQL(
	FROM events
	JOIN contexts USING (context)
	JOIN names USING (name)
);

static char where[QueryCap] = SQL(
	WHERE true
);

static void append(char query[static QueryCap], const char *sql) {
	size_t len = strlen(query);
	snprintf(&query[len], QueryCap - len, " %s", sql);
}

static struct Bind {
	const char *param;
	const char *text;
	int value;
} Bind(const char *param, const char *text, int value) {
	return (struct Bind) { param, text, value };
}

static const char *TypeNames[] = {
#define X(id, name) [id] = name,
	ENUM_TYPE
#undef X
};

static enum Type parseType(const char *input) {
	for (enum Type type = 0; type < ARRAY_LEN(TypeNames); ++type) {
		if (!strcmp(input, TypeNames[type])) return type;
	}
	errx(EX_USAGE, "no such type %s", input);
}

int main(int argc, char *argv[]) {
	bool tty = isatty(STDOUT_FILENO);

	bool shell = false;
	const char *path = NULL;
	Format *format = (tty ? formatColor : formatPlain);

	bool sort = false;
	bool group = false;
	const char *limit = NULL;

	int n = 0;
	struct Bind binds[argc + 2];
	const char *Opts = "D:F:LN:ST:a:b:c:d:f:gh:l:m:n:pqst:u:vw:";
	for (int opt; 0 < (opt = getopt(argc, argv, Opts));) {
		switch (opt) {
			break; case 'D': {
				append(
					where,
					SQL(
						AND events.time >= strftime('%s', :date, 'start of day')
						AND events.time
							< strftime('%s', :date, 'start of day', '+1 day')
					)
				);
				binds[n++] = Bind(":date", optarg, 0);
			}
			break; case 'F': {
				binds[n++] = Bind(":format", optarg, 0);
			}
			break; case 'L': {
				binds[n++] = Bind(":local", NULL, 1);
			}
			break; case 'N': {
				append(where, SQL(AND contexts.network = :network));
				binds[n++] = Bind(":network", optarg, 0);
			}
			break; case 'S': {
				shell = true;
			}
			break; case 'T': {
				append(where, SQL(AND events.target = :target));
				binds[n++] = Bind(":target", optarg, 0);
			}
			break; case 'a': {
				append(where, SQL(AND events.time >= strftime('%s', :after)));
				binds[n++] = Bind(":after", optarg, 0);
			}
			break; case 'b': {
				append(where, SQL(AND events.time < strftime('%s', :before)));
				binds[n++] = Bind(":before", optarg, 0);
			}
			break; case 'c': {
				append(where, SQL(AND contexts.name = :context));
				binds[n++] = Bind(":context", optarg, 0);
			}
			break; case 'd': {
				path = optarg;
			}
			break; case 'f': {
				format = parseFormat(optarg);
			}
			break; case 'g': {
				group = true;
				sort = true;
			}
			break; case 'h': {
				append(where, SQL(AND names.host = :host));
				binds[n++] = Bind(":host", optarg, 0);
			}
			break; case 'l': {
				limit = optarg;
				sort = true;
			}
			break; case 'm': {
				append(where, SQL(AND events.message REGEXP :regexp));
				binds[n++] = Bind(":regexp", optarg, 0);
			}
			break; case 'n': {
				append(where, SQL(AND names.nick = :nick));
				binds[n++] = Bind(":nick", optarg, 0);
			}
			break; case 'p': {
				append(where, SQL(AND contexts.query = :query));
				binds[n++] = Bind(":query", NULL, 0);
			}
			break; case 'q': {
				append(where, SQL(AND contexts.query = :query));
				binds[n++] = Bind(":query", NULL, 1);
			}
			break; case 's': {
				sort = true;
			}
			break; case 't': {
				append(where, SQL(AND events.type = :type));
				binds[n++] = Bind(":type", NULL, parseType(optarg));
			}
			break; case 'u': {
				append(where, SQL(AND names.user = :user));
				binds[n++] = Bind(":user", optarg, 0);
			}
			break; case 'v': {
				verbose = true;
			}
			break; case 'w': {
				append(where, "AND");
				append(where, optarg);
			}
			break; default: return EX_USAGE;
		}
	}

	if (optind < argc) {
		append(select, SQL(highlight(search, 6, :open, :close)));
		append(from, SQL(JOIN search ON search.rowid = events.event));
		append(where, SQL(AND search MATCH :search));
		binds[n++] = Bind(":search", argv[optind], 0);
		if (format == formatColor) {
			binds[n++] = Bind(":open", "\33[7m", 0);
			binds[n++] = Bind(":close", "\33[27m", 0);
		} else {
			// XXX: If you leave these NULL fts5 segfaults...
			binds[n++] = Bind(":open", "", 0);
			binds[n++] = Bind(":close", "", 0);
		}
	} else {
		append(select, SQL(events.message));
	}

	if (limit) {
		append(where, SQL(ORDER BY time DESC, event DESC LIMIT :limit));
		binds[n++] = Bind(":limit", limit, 0);
	}

	dbFind(path, SQLITE_OPEN_READWRITE);
	if (dbVersion() != DatabaseVersion) {
		errx(EX_CONFIG, "database out of date; migrate with litterbox -m");
	}
	sqlite3_create_function(
		db, "regexp", 2, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL,
		regexp, NULL, NULL
	);

	if (shell) {
		path = strdup(sqlite3_db_filename(db, "main"));
		if (!path) err(EX_OSERR, "strdup");
		dbClose();
		execlp(SQLITE3_BIN, "sqlite3", path, NULL);
		err(EX_UNAVAILABLE, "sqlite3");
	}

	int len;
	char *query = NULL;
	if (sort) {
		len = asprintf(
			&query,
			SQL(
				WITH results AS (%s %s %s)
				SELECT * FROM results
				ORDER BY %s time, event;
			),
			select, from, where, (group ? "network, context," : "")
		);
	} else {
		len = asprintf(&query, "%s %s %s;", select, from, where);
	}
	if (len < 0) err(EX_OSERR, "asprintf");

	sqlite3_stmt *stmt = dbPrepare(query);
	free(query);

	for (int i = 0; i < n; ++i) {
		if (binds[i].text) {
			dbBindText(stmt, binds[i].param, binds[i].text);
		} else {
			dbBindInt(stmt, binds[i].param, binds[i].value);
		}
	}

	if (verbose) {
		char *expand = sqlite3_expanded_sql(stmt);
		if (!expand) errx(EX_SOFTWARE, "sqlite3_expanded_sql");
		fprintf(stderr, "%s\n", expand);
		sqlite3_free(expand);
	}

	if (tty) {
		const char *shell = getenv("SHELL");
		const char *pager = getenv("PAGER");
		if (!shell) shell = "/bin/sh";
		if (!pager) pager = "less";
		setenv("LESS", "FRX", 0);

		int rw[2];
		int error = pipe(rw);
		if (error) err(EX_OSERR, "pipe");

		pid_t pid = fork();
		if (pid < 0) err(EX_OSERR, "fork");

		if (!pid) {
			dup2(rw[0], STDIN_FILENO);
			close(rw[0]);
			close(rw[1]);
			execl(shell, shell, "-c", pager, NULL);
			err(EX_CONFIG, "%s", shell);
		}

		dup2(rw[1], STDOUT_FILENO);
		close(rw[0]);
		close(rw[1]);
		setlinebuf(stdout);
	}

	int result;
	while (SQLITE_ROW == (result = sqlite3_step(stmt))) {
		struct Event event = {
			.network = (const char *)sqlite3_column_text(stmt, 1),
			.context = (const char *)sqlite3_column_text(stmt, 2),
			.time    = (const char *)sqlite3_column_text(stmt, 3),
			.type    = sqlite3_column_int(stmt, 4),
			.nick    = (const char *)sqlite3_column_text(stmt, 5),
			.user    = (const char *)sqlite3_column_text(stmt, 6),
			.host    = (const char *)sqlite3_column_text(stmt, 7),
			.target  = (const char *)sqlite3_column_text(stmt, 8),
			.message = (const char *)sqlite3_column_text(stmt, 9),
		};
		if (!event.target) event.target = "";
		if (!event.message) event.message = "";
		format(group, event);
	}
	if (result != SQLITE_DONE) warnx("%s", sqlite3_errmsg(db));

	sqlite3_finalize(stmt);
	dbClose();

	if (tty) {
		fclose(stdout);
		int status;
		wait(&status);
	}
}
