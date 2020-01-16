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

#define NICK "\33[%dm%s\33[m"
	switch (e.type) {
		break; case Privmsg: {
			printf("<" NICK "> %s\n", color(e.user), e.nick, ansi(e.message));
		}
		break; case Notice: {
			printf("-" NICK "- %s\n", color(e.user), e.nick, ansi(e.message));
		}
		break; case Action: {
			printf("* " NICK " %s\n", color(e.user), e.nick, ansi(e.message));
		}
		break; case Join: {
			printf(NICK " joined\n", color(e.user), e.nick);
		}
		break; case Part: {
			printf(NICK " parted: %s\n", color(e.user), e.nick, ansi(e.message));
		}
		break; case Quit: {
			printf(NICK " quit: %s\n", color(e.user), e.nick, ansi(e.message));
		}
		break; case Kick: {
			printf(
				NICK " kicked %s: %s\n",
				color(e.user), e.nick, e.target, ansi(e.message)
			);
		}
		break; case Nick: {
			printf(
				NICK " changed nick to " NICK "\n",
				color(e.user), e.nick, color(e.user), e.target
			);
		}
		break; case Topic: {
			printf(
				NICK "set the topic: %s\n",
				color(e.user), e.nick, ansi(e.message)
			);
		}
	}
#undef NICK
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
	}
}

static const char *Inner = SQL(
	SELECT
		contexts.network,
		contexts.name AS context,
		CASE WHEN :local THEN
			strftime(
				coalesce(:format, '%Y-%m-%dT%H:%M:%S'),
				events.time,
				'localtime'
			)
		ELSE
			strftime(
				coalesce(:format, '%Y-%m-%dT%H:%M:%SZ'),
				events.time
			)
		END AS time,
		events.type,
		names.nick,
		names.user,
		names.host,
		events.target,
		highlight(search, 6, :open, :close),
		events.event
	FROM events
	JOIN contexts USING (context)
	JOIN names USING (name)
	JOIN search ON search.rowid = events.event
	WHERE coalesce(contexts.network = :network, true)
		AND coalesce(contexts.name = :context, true)
		AND coalesce(contexts.query = :query, true)
		AND coalesce(date(events.time) = date(:date), true)
		AND coalesce(events.time >= datetime(:after), true)
		AND coalesce(events.time <= datetime(:before), true)
		AND coalesce(events.type = :type, true)
		AND coalesce(names.nick = :nick, true)
		AND coalesce(names.user = :user, true)
		AND coalesce(names.host = :host, true)
		AND coalesce(events.target = :target, true)
		AND coalesce(events.message REGEXP :regexp, true)
);

static const char *Search = SQL(search MATCH :search);

static const char *Limit = SQL(
	ORDER BY time DESC, event DESC
	LIMIT coalesce(:limit, -1)
);

static const char *Outer = SQL(
	SELECT * FROM results
	ORDER BY time, event
);

static const char *Group = SQL(
	SELECT * FROM results
	ORDER BY network, context, time, event
);

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

static struct Bind {
	const char *param;
	const char *text;
	int value;
} Bind(const char *param, const char *text, int value) {
	return (struct Bind) { param, text, value };
}

int main(int argc, char *argv[]) {
	bool tty = isatty(STDOUT_FILENO);

	char *path = NULL;
	bool shell = false;
	bool group = false;
	Format *format = (tty ? formatColor : formatPlain);

	int n = 0;
	struct Bind binds[argc];
	const char *search = NULL;
	const char *where = NULL;

	int opt;
	const char *Opts = "D:F:LN:T:a:b:c:d:f:gh:l:m:n:pqst:u:vw:";
	while (0 < (opt = getopt(argc, argv, Opts))) {
		switch (opt) {
			break; case 'D': binds[n++] = Bind(":date", optarg, 0);
			break; case 'F': binds[n++] = Bind(":format", optarg, 0);
			break; case 'L': binds[n++] = Bind(":local", NULL, 1);
			break; case 'N': binds[n++] = Bind(":network", optarg, 0);
			break; case 'T': binds[n++] = Bind(":target", optarg, 0);
			break; case 'a': binds[n++] = Bind(":after", optarg, 0);
			break; case 'b': binds[n++] = Bind(":before", optarg, 0);
			break; case 'c': binds[n++] = Bind(":context", optarg, 0);
			break; case 'd': path = optarg;
			break; case 'f': format = parseFormat(optarg);
			break; case 'g': group = true;
			break; case 'h': binds[n++] = Bind(":host", optarg, 0);
			break; case 'l': binds[n++] = Bind(":limit", optarg, 0);
			break; case 'm': binds[n++] = Bind(":regexp", optarg, 0);
			break; case 'n': binds[n++] = Bind(":nick", optarg, 0);
			break; case 'p': binds[n++] = Bind(":query", NULL, 0);
			break; case 'q': binds[n++] = Bind(":query", NULL, 1);
			break; case 's': shell = true;
			break; case 't': binds[n++] = Bind(":type", NULL, parseType(optarg));
			break; case 'u': binds[n++] = Bind(":user", optarg, 0);
			break; case 'v': verbose = true;
			break; case 'w': where = optarg;
			break; default:  return EX_USAGE;
		}
	}
	if (optind < argc) search = argv[optind];

	if (shell) {
		dbFind(path, SQLITE_OPEN_READONLY);
		path = strdup(sqlite3_db_filename(db, "main"));
		if (!path) err(EX_OSERR, "strdup");
		dbClose();
		execlp("sqlite3", "sqlite3", path, NULL);
		err(EX_UNAVAILABLE, "sqlite3");
	}

	if (tty) {
		const char *pager = getenv("PAGER");
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
			execlp(pager, pager, NULL);
			err(EX_CONFIG, "%s", pager);
		}

		dup2(rw[1], STDOUT_FILENO);
		close(rw[0]);
		close(rw[1]);
	}

	dbFind(path, SQLITE_OPEN_READWRITE);
	if (dbVersion() != DatabaseVersion) {
		errx(EX_CONFIG, "database out of date; migrate with litterbox -m");
	}
	sqlite3_create_function(
		db, "regexp", 2, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL,
		regexp, NULL, NULL
	);


	int len;
	char sql[4096];
	if (search) {
		len = snprintf(
			sql, sizeof(sql),
			"WITH results AS (%s AND %s AND %s %s) %s;",
			Inner, Search, (where ? where : "true"), Limit,
			(group ? Group : Outer)
		);
		binds[n++] = Bind(":search", search, 0);
	} else {
		len = snprintf(
			sql, sizeof(sql),
			"WITH results AS (%s AND %s %s) %s;",
			Inner, (where ? where : "true"), Limit, (group ? Group : Outer)
		);
	}
	assert((size_t)len < sizeof(sql));

	sqlite3_stmt *stmt = dbPrepare(sql);
	for (int i = 0; i < n; ++i) {
		if (binds[i].text) {
			dbBindText(stmt, binds[i].param, binds[i].text);
		} else {
			dbBindInt(stmt, binds[i].param, binds[i].value);
		}
	}

	if (format == formatColor) {
		dbBindText(stmt, ":open", "\33[7m");
		dbBindText(stmt, ":close", "\33[27m");
	} else {
		// XXX: If you leave these NULL fts5 segfaults...
		dbBindText(stmt, ":open", "");
		dbBindText(stmt, ":close", "");
	}

	if (verbose) {
		char *expand = sqlite3_expanded_sql(stmt);
		if (!expand) errx(EX_SOFTWARE, "sqlite3_expanded_sql");
		fprintf(stderr, "%s\n", expand);
		sqlite3_free(expand);
	}

	int result;
	while (SQLITE_ROW == (result = sqlite3_step(stmt))) {
		struct Event event = {
			.network = (const char *)sqlite3_column_text(stmt, 0),
			.context = (const char *)sqlite3_column_text(stmt, 1),
			.time    = (const char *)sqlite3_column_text(stmt, 2),
			.type    = sqlite3_column_int(stmt, 3),
			.nick    = (const char *)sqlite3_column_text(stmt, 4),
			.user    = (const char *)sqlite3_column_text(stmt, 5),
			.host    = (const char *)sqlite3_column_text(stmt, 6),
			.target  = (const char *)sqlite3_column_text(stmt, 7),
			.message = (const char *)sqlite3_column_text(stmt, 8),
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
