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
#include <errno.h>
#include <limits.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sysexits.h>

#define SQL(...) #__VA_ARGS__
#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

#define DATABASE_PATH "litterbox/litterbox.sqlite"

enum { DatabaseVersion = 0 };

enum Type {
	Privmsg,
	Notice,
	Action,
	Join,
	Part,
	Quit,
	Kick,
	Nick,
	Topic,
};

static bool verbose;

static inline void dbExec(sqlite3 *db, const char *sql) {
	int error = sqlite3_exec(db, sql, NULL, NULL, NULL);
	if (error) errx(EX_SOFTWARE, "%s: %s", sqlite3_errmsg(db), sql);
}

static inline sqlite3 *dbOpen(char *path, int flags) {
	char *base = strrchr(path, '/');
	if (flags & SQLITE_OPEN_CREATE && base) {
		*base = '\0';
		int error = mkdir(path, 0700);
		if (error && errno != EEXIST) err(EX_CANTCREAT, "%s", path);
		*base = '/';
	}

	sqlite3 *db;
	int error = sqlite3_open_v2(path, &db, flags, NULL);
	if (error == SQLITE_CANTOPEN) {
		sqlite3_close(db);
		return NULL;
	}
	if (error) errx(EX_NOINPUT, "%s: %s", path, sqlite3_errmsg(db));

	sqlite3_busy_timeout(db, 1000);
	dbExec(db, SQL(PRAGMA foreign_keys = true;));

	return db;
}

static inline sqlite3 *dbFind(char *path, int flags) {
	if (path) return dbOpen(path, flags);

	const char *home = getenv("HOME");
	const char *dataHome = getenv("XDG_DATA_HOME");
	const char *dataDirs = getenv("XDG_DATA_DIRS");

	char buf[PATH_MAX];
	if (dataHome) {
		snprintf(buf, sizeof(buf), "%s/" DATABASE_PATH, dataHome);
	} else {
		if (!home) errx(EX_CONFIG, "HOME unset");
		snprintf(buf, sizeof(buf), "%s/.local/share/" DATABASE_PATH, home);
	}
	sqlite3 *db = dbOpen(buf, flags);
	if (db) return db;

	if (!dataDirs) dataDirs = "/usr/local/share:/usr/share";
	while (*dataDirs) {
		size_t len = strcspn(dataDirs, ":");
		snprintf(buf, sizeof(buf), "%.*s/" DATABASE_PATH, (int)len, dataDirs);
		db = dbOpen(buf, flags);
		if (db) return db;
		dataDirs += len;
		if (*dataDirs) dataDirs++;
	}
	return NULL;
}

static inline sqlite3_stmt *
dbPrepare(sqlite3 *db, bool persistent, const char *sql) {
	sqlite3_stmt *stmt;
	int error = sqlite3_prepare_v3(
		db, sql, -1, (persistent ? SQLITE_PREPARE_PERSISTENT : 0), &stmt, NULL
	);
	if (error) errx(EX_SOFTWARE, "%s: %s", sqlite3_errmsg(db), sql);
	return stmt;
}

static inline int dbParam(sqlite3_stmt *stmt, const char *param) {
	int index = sqlite3_bind_parameter_index(stmt, param);
	if (index) return index;
	errx(
		EX_SOFTWARE, "no such parameter %s: %s",
		param, sqlite3_sql(stmt)
	);
}

static inline void dbBindNull(sqlite3_stmt *stmt, const char *param) {
	if (!sqlite3_bind_null(stmt, dbParam(stmt, param))) return;
	errx(
		EX_SOFTWARE, "sqlite3_bind_null: %s",
		sqlite3_errmsg(sqlite3_db_handle(stmt))
	);
}

static inline void
dbBindInt(sqlite3_stmt *stmt, const char *param, int value) {
	if (!sqlite3_bind_int(stmt, dbParam(stmt, param), value)) return;
	errx(
		EX_SOFTWARE, "sqlite3_bind_int: %s",
		sqlite3_errmsg(sqlite3_db_handle(stmt))
	);
}

static inline void dbBindText5(
	sqlite3_stmt *stmt, const char *param,
	const char *text, int len, bool copy
) {
	int error = sqlite3_bind_text(
		stmt, dbParam(stmt, param), text, len, (copy ? SQLITE_TRANSIENT : NULL)
	);
	if (!error) return;
	errx(
		EX_SOFTWARE, "sqlite3_bind_text: %s",
		sqlite3_errmsg(sqlite3_db_handle(stmt))
	);
}

static inline void
dbBindText(sqlite3_stmt *stmt, const char *param, const char *text) {
	dbBindText5(stmt, param, text, -1, false);
}

static inline void
dbBindTextLen(sqlite3_stmt *stmt, const char *param, const char *text, int len) {
	dbBindText5(stmt, param, text, len, false);
}

static inline void
dbBindTextCopy(sqlite3_stmt *stmt, const char *param, const char *text) {
	dbBindText5(stmt, param, text, -1, true);
}

static inline int dbStep(sqlite3_stmt *stmt) {
	int error = sqlite3_step(stmt);
	if (error == SQLITE_ROW || error == SQLITE_DONE) return error;
	errx(
		EX_SOFTWARE, "%s: %s",
		sqlite3_errmsg(sqlite3_db_handle(stmt)), sqlite3_expanded_sql(stmt)
	);
}

static inline void dbRun(sqlite3_stmt *stmt) {
	dbStep(stmt);
	if (verbose && sqlite3_changes(sqlite3_db_handle(stmt))) {
		char *sql = sqlite3_expanded_sql(stmt);
		if (sql) fprintf(stderr, "%s\n", sql);
		sqlite3_free(sql);
	}
	sqlite3_reset(stmt);
}

static inline int dbVersion(sqlite3 *db) {
	sqlite3_stmt *stmt = dbPrepare(db, false, SQL(PRAGMA user_version;));
	dbStep(stmt);
	int version = sqlite3_column_int(stmt, 0);
	sqlite3_finalize(stmt);
	return version;
}

static const char *InitSQL = SQL(
	BEGIN TRANSACTION;

	CREATE TABLE contexts (
		context INTEGER PRIMARY KEY,
		network TEXT NOT NULL,
		name TEXT NOT NULL,
		query BOOLEAN NOT NULL,
		UNIQUE (network, name)
	);

	CREATE TABLE names (
		name INTEGER PRIMARY KEY,
		nick TEXT NOT NULL,
		user TEXT NOT NULL,
		host TEXT NOT NULL,
		UNIQUE (nick, user, host)
	);

	CREATE TABLE events (
		event INTEGER PRIMARY KEY,
		time DATETIME NOT NULL,
		type INTEGER NOT NULL,
		context INTEGER NOT NULL REFERENCES contexts,
		name INTEGER NOT NULL REFERENCES names,
		target TEXT,
		message TEXT
	);

	CREATE VIEW text (
		event, network, channel, query, nick, user, target, message
	) AS
	SELECT
		event, network,
		CASE WHEN query THEN NULL ELSE contexts.name END,
		CASE WHEN query THEN contexts.name ELSE NULL END,
		nick, user, target, message
	FROM events
	JOIN contexts USING (context)
	JOIN names ON names.name = events.name;

	CREATE VIRTUAL TABLE search USING fts5 (
		network, channel, query, nick, user, target, message,
		content = text,
		content_rowid = event,
		tokenize = 'porter'
	);

	CREATE TRIGGER eventsInsert AFTER INSERT ON events BEGIN
		INSERT INTO search (
			rowid, network, channel, query, nick, user, target, message
		) SELECT * FROM text WHERE event = new.event;
	END;

	CREATE TRIGGER eventsDelete AFTER DELETE ON events BEGIN
		INSERT INTO search (
			search, rowid, network, channel, query, nick, user, target, message
		) SELECT 'delete', * FROM text WHERE event = old.event;
	END;

	COMMIT TRANSACTION;
);

static inline void dbInit(sqlite3 *db) {
	dbExec(db, InitSQL);
}

static const char *MigrationSQL[] = {
	NULL,
};

static inline void dbMigrate(sqlite3 *db) {
	for (int version = dbVersion(db); version < DatabaseVersion; ++version) {
		dbExec(db, MigrationSQL[version]);
	}
}
