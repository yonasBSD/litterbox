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

#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <unistd.h>

#include "database.h"

static const char *Inner = SQL(
	SELECT
		contexts.network,
		contexts.name AS context,
		date(events.time) || 'T' || time(events.time) || 'Z' AS time,
		events.type,
		names.nick,
		CASE WHEN names.user = '*'
			THEN names.nick
			ELSE names.user
		END,
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
		AND coalesce(events.type = :type, true)
		AND coalesce(names.nick = :nick, true)
		AND coalesce(names.user = :user, true)
		AND coalesce(names.host = :host, true)
		AND coalesce(events.target = :target, true)
);

static const char *Search = SQL(search MATCH :search);

static const char *Limit = SQL(
	ORDER BY time DESC, event DESC
	LIMIT :limit
);

static const char *Outer = SQL(
	SELECT * FROM results
	ORDER BY time, event
);

typedef void Format(
	const char *network, const char *context, const char *time, enum Type type,
	const char *nick, const char *user, const char *target, const char *message
);

static void formatPlain(
	const char *network, const char *context, const char *time, enum Type type,
	const char *nick, const char *user, const char *target, const char *message
) {
	(void)user;
	if (!target) target = "";
	if (!message) message = "";
	printf("%s/%s: [%s] ", network, context, time);
	switch (type) {
		break; case Privmsg: printf("<%s> %s\n", nick, message);
		break; case Notice: printf("-%s- %s\n", nick, message);
		break; case Action: printf("* %s %s\n", nick, message);
		break; case Join: printf("%s joined\n", nick);
		break; case Part: printf("%s parted: %s\n", nick, message);
		break; case Quit: printf("%s quit: %s\n", nick, message);
		break; case Kick: printf("%s kicked %s: %s\n", nick, target, message);
		break; case Nick: printf("%s changed nick to %s\n", nick, target);
		break; case Topic: printf("%s set the topic: %s\n", nick, message);
	}
}

static const int Colors[] = {
	31, 32, 33, 34, 35, 36, 37,
	90, 91, 92, 93, 94, 95, 96, 97,
};

static int color(const char *user) {
	if (*user == '~') user++;
	uint32_t hash = 0;
	for (; *user; ++user) {
		hash = (hash << 5) | (hash >> 27);
		hash ^= *user;
		hash *= 0x27220A95;
	}
	return Colors[hash % ARRAY_LEN(Colors)];
}

static void formatColor(
	const char *network, const char *context, const char *time, enum Type type,
	const char *nick, const char *user, const char *target, const char *message
) {
	if (!target) target = "";
	if (!message) message = "";
	printf("%s/%s: [%s] ", network, context, time);
	switch (type) {
		break; case Privmsg:
			printf("<\33[%dm%s\33[m> %s\n", color(user), nick, message);
		break; case Notice:
			printf("-\33[%dm%s\33[m- %s\n", color(user), nick, message);
		break; case Action:
			printf("* \33[%dm%s\33[m %s\n", color(user), nick, message);
		break; case Join:
			printf("\33[%dm%s\33[m joined\n", color(user), nick);
		break; case Part:
			printf("\33[%dm%s\33[m parted: %s\n", color(user), nick, message);
		break; case Quit:
			printf("\33[%dm%s\33[m quit: %s\n", color(user), nick, message);
		break; case Kick:
			printf(
				"\33[%dm%s\33[m kicked %s: %s\n",
				color(user), nick, target, message
			);
		break; case Nick:
			printf(
				"\33[%dm%s\33[m changed nick to \33[%dm%s\33[m\n",
				color(user), nick, color(user), target
			);
		break; case Topic:
			printf(
				"\33[%dm%s\33[m set the topic: %s\n",
				color(user), nick, message
			);
	}
}

static const char *TypeNames[] = {
#define X(id, name) [id] = name,
	ENUM_TYPE
#undef X
};

static const enum Type *parseType(const char *input) {
	static enum Type type;
	for (type = 0; type < ARRAY_LEN(TypeNames); ++type) {
		if (!strcmp(input, TypeNames[type])) return &type;
	}
	errx(EX_USAGE, "no such type %s", input);
}

int main(int argc, char *argv[]) {
	char *path = NULL;
	bool shell = false;

	bool public = false;
	bool query = false;
	const char *network = NULL;
	const char *context = NULL;
	const char *date = NULL;
	const enum Type *type = NULL;
	const char *nick = NULL;
	const char *user = NULL;
	const char *host = NULL;
	const char *target = NULL;
	const char *search = NULL;
	int limit = -1;

	int opt;
	while (0 < (opt = getopt(argc, argv, "D:N:T:c:d:h:l:n:pqst:u:v"))) {
		switch (opt) {
			break; case 'D': date = optarg;
			break; case 'N': network = optarg;
			break; case 'T': target = optarg;
			break; case 'c': context = optarg;
			break; case 'd': path = optarg;
			break; case 'h': host = optarg;
			break; case 'l': limit = strtol(optarg, NULL, 0);
			break; case 'n': nick = optarg;
			break; case 'p': public = true;
			break; case 'q': query = true;
			break; case 's': shell = true;
			break; case 't': type = parseType(optarg);
			break; case 'u': user = optarg;
			break; case 'v': verbose = true;
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

	bool tty = isatty(STDOUT_FILENO);
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

	dbFind(path, SQLITE_OPEN_READONLY);
	if (dbVersion() != DatabaseVersion) {
		errx(EX_CONFIG, "database out of date; migrate with litterbox -m");
	}

	char sql[4096];
	if (search) {
		snprintf(
			sql, sizeof(sql),
			"WITH results AS (%s AND %s %s) %s;",
			Inner, Search, Limit, Outer
		);
	} else {
		snprintf(
			sql, sizeof(sql),
			"WITH results AS (%s %s) %s;",
			Inner, Limit, Outer
		);
	}

	sqlite3_stmt *stmt = dbPrepare(sql);
	dbBindText(stmt, ":network", network);
	dbBindText(stmt, ":context", context);
	if (public) dbBindInt(stmt, ":query", false);
	if (query) dbBindInt(stmt, ":query", true);
	dbBindText(stmt, ":date", date);
	if (type) dbBindInt(stmt, ":type", *type);
	dbBindText(stmt, ":nick", nick);
	dbBindText(stmt, ":user", user);
	dbBindText(stmt, ":host", host);
	dbBindText(stmt, ":target", target);
	if (search) dbBindText(stmt, ":search", search);
	dbBindInt(stmt, ":limit", limit);

	if (tty) {
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

	Format *format = (tty ? formatColor : formatPlain);

	int result;
	while (SQLITE_ROW == (result = sqlite3_step(stmt))) {
		int i = 0;
		const char *network = (const char *)sqlite3_column_text(stmt, i++);
		const char *context = (const char *)sqlite3_column_text(stmt, i++);
		const char *time = (const char *)sqlite3_column_text(stmt, i++);
		enum Type type = sqlite3_column_int(stmt, i++);
		const char *nick = (const char *)sqlite3_column_text(stmt, i++);
		const char *user = (const char *)sqlite3_column_text(stmt, i++);
		const char *target = (const char *)sqlite3_column_text(stmt, i++);
		const char *message = (const char *)sqlite3_column_text(stmt, i++);
		format(network, context, time, type, nick, user, target, message);
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
