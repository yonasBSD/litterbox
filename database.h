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
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sysexits.h>

#define SQL(...) #__VA_ARGS__
#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

const char *configPath(const char **dirs, const char *path);
const char *dataPath(const char **dirs, const char *path);
FILE *configOpen(const char *path, const char *mode);
FILE *dataOpen(const char *path, const char *mode);
void dataMkdir(const char *path);
int getopt_config(
	int argc, char *const *argv, const char *optstring,
	const struct option *longopts, int *longindex
);

static const char *DatabasePath = "litterbox.sqlite";

enum { DatabaseVersion = 5 };

#define ENUM_TYPE \
	X(Privmsg, "privmsg") \
	X(Notice, "notice") \
	X(Action, "action") \
	X(Join, "join") \
	X(Part, "part") \
	X(Quit, "quit") \
	X(Kick, "kick") \
	X(Nick, "nick") \
	X(Topic, "topic") \
	X(Ban, "ban") \
	X(Unban, "unban")

enum Type {
#define X(id, _) id,
	ENUM_TYPE
#undef X
};

static inline uint32_t hash(const char *user) {
	if (*user == '~') user++;
	uint32_t hash = 0;
	for (; *user; ++user) {
		hash = (hash << 5) | (hash >> 27);
		hash ^= *user;
		hash *= 0x27220A95;
	}
	return hash;
}

static bool verbose;
static sqlite3 *db;

static inline void dbExec(const char *sql) {
	int error = sqlite3_exec(db, sql, NULL, NULL, NULL);
	if (error) errx(EX_SOFTWARE, "%s: %s", sqlite3_errmsg(db), sql);
}

static inline void dbOpen(const char *path, int flags) {
	int error = sqlite3_open_v2(path, &db, flags, NULL);
	if (error == SQLITE_CANTOPEN) {
		sqlite3_close(db);
		db = NULL;
		return;
	}
	if (error) errx(EX_NOINPUT, "%s: %s", path, sqlite3_errmsg(db));

	sqlite3_busy_timeout(db, 10000);
	dbExec(SQL(PRAGMA journal_mode = WAL;));
	dbExec(SQL(PRAGMA foreign_keys = true;));
}

static inline void dbFind(const char *path, int flags) {
	if (path) {
		dbOpen(path, flags);
		if (db) return;
		errx(EX_NOINPUT, "%s: database not found", path);
	}

	if (flags & SQLITE_OPEN_CREATE) {
		dataMkdir("");
	}

	const char *dirs = NULL;
	while (NULL != (path = dataPath(&dirs, DatabasePath))) {
		dbOpen(path, flags);
		if (db) return;
	}
	errx(EX_NOINPUT, "database not found; initialize it with litterbox -i");
}

static struct Persist {
	sqlite3_stmt *stmt;
	struct Persist *prev;
} *persistHead;

static inline void dbPersist(sqlite3_stmt **stmt, const char *sql) {
	if (*stmt) return;

	int error = sqlite3_prepare_v3(
		db, sql, -1, SQLITE_PREPARE_PERSISTENT, stmt, NULL
	);
	if (error) errx(EX_SOFTWARE, "%s: %s", sqlite3_errmsg(db), sql);

	struct Persist *persist = malloc(sizeof(*persist));
	persist->stmt = *stmt;
	persist->prev = persistHead;
	persistHead = persist;
}

static inline void dbClose(void) {
	for (struct Persist *persist = persistHead; persist;) {
		sqlite3_finalize(persist->stmt);
		struct Persist *prev = persist->prev;
		free(persist);
		persist = prev;
	}
	dbExec(SQL(PRAGMA optimize;));
	sqlite3_close(db);
}

static inline sqlite3_stmt *dbPrepare(const char *sql) {
	sqlite3_stmt *stmt;
	int error = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (error) errx(EX_SOFTWARE, "%s: %s", sqlite3_errmsg(db), sql);
	return stmt;
}

static inline int dbParam(sqlite3_stmt *stmt, const char *param) {
	int index = sqlite3_bind_parameter_index(stmt, param);
	if (index) return index;
	errx(EX_SOFTWARE, "no such parameter %s: %s", param, sqlite3_sql(stmt));
}

static inline void dbBindNull(sqlite3_stmt *stmt, const char *param) {
	if (!sqlite3_bind_null(stmt, dbParam(stmt, param))) return;
	errx(EX_SOFTWARE, "sqlite3_bind_null: %s", sqlite3_errmsg(db));
}

static inline void
dbBindInt(sqlite3_stmt *stmt, const char *param, sqlite3_int64 value) {
	if (!sqlite3_bind_int64(stmt, dbParam(stmt, param), value)) return;
	errx(EX_SOFTWARE, "sqlite3_bind_int64: %s", sqlite3_errmsg(db));
}

static inline void dbBindText5(
	sqlite3_stmt *stmt, const char *param,
	const char *text, int len, bool copy
) {
	int error = sqlite3_bind_text(
		stmt, dbParam(stmt, param), text, len, (copy ? SQLITE_TRANSIENT : NULL)
	);
	if (error) err(EX_SOFTWARE, "sqlite3_bind_text: %s", sqlite3_errmsg(db));
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
	errx(EX_SOFTWARE, "%s: %s", sqlite3_errmsg(db), sqlite3_expanded_sql(stmt));
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

static inline int dbVersion(void) {
	sqlite3_stmt *stmt = dbPrepare(SQL(PRAGMA user_version;));
	dbStep(stmt);
	int version = sqlite3_column_int(stmt, 0);
	sqlite3_finalize(stmt);
	return version;
}

static const char *InitSQL = SQL(
	BEGIN TRANSACTION;

	CREATE TABLE motds (
		time DATETIME NOT NULL,
		network TEXT NOT NULL,
		motd TEXT NOT NULL,
		UNIQUE (network, motd)
	);

	CREATE TABLE contexts (
		context INTEGER PRIMARY KEY,
		network TEXT NOT NULL,
		name TEXT NOT NULL,
		query BOOLEAN NOT NULL,
		UNIQUE (network, name)
	);

	CREATE TABLE topics (
		time DATETIME NOT NULL,
		context INTEGER NOT NULL REFERENCES contexts,
		topic TEXT NOT NULL,
		UNIQUE (context, topic)
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
	CREATE INDEX eventsContextTime ON events (context, time);

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
	JOIN names USING (name);

	CREATE VIRTUAL TABLE search USING fts5 (
		network, channel, query, nick, user, target, message,
		content = text,
		content_rowid = event,
		tokenize = 'porter',
		columnsize = 0
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

	CREATE TABLE consumers (
		host STRING NOT NULL,
		port INTEGER NOT NULL,
		pos INTEGER NOT NULL,
		UNIQUE (host, port)
	);

	PRAGMA user_version = 5;

	COMMIT TRANSACTION;
);

static inline void dbInit(void) {
	dbExec(InitSQL);
}

static const char *MigrationSQL[] = {
	// Added columnsize = 0 option.
	SQL(
		DROP TABLE search;
		CREATE VIRTUAL TABLE search USING fts5 (
			network, channel, query, nick, user, target, message,
			content = text,
			content_rowid = event,
			tokenize = 'porter',
			columnsize = 0
		);
		INSERT INTO search (
			rowid, network, channel, query, nick, user, target, message
		) SELECT * FROM text;
		PRAGMA user_version = 1;
	),

	SQL(
		CREATE TABLE consumers (
			host STRING NOT NULL,
			port INTEGER NOT NULL,
			pos INTEGER NOT NULL,
			UNIQUE (host, port)
		);
		PRAGMA user_version = 2;
	),

	SQL(
		// When migrating from version 2, wait to create index until after
		// times are converted in version 4.
		// CREATE INDEX eventsTime ON events (time);
		PRAGMA user_version = 3;
	),

	SQL(
		UPDATE motds SET time = strftime('%s', time);
		UPDATE topics SET time = strftime('%s', time);
		UPDATE events SET time = strftime('%s', time);
		// Don't bother creating the index that will be immediately dropped in
		// version 5.
		// CREATE INDEX IF NOT EXISTS eventsTime ON events (time);
		PRAGMA user_version = 4;
	),

	SQL(
		DROP INDEX IF EXISTS eventsTime;
		CREATE INDEX eventsContextTime ON events (context, time);
		PRAGMA user_version = 5;
	),
};

static inline void dbMigrate(void) {
	dbExec(SQL(BEGIN TRANSACTION;));
	for (int version = dbVersion(); version < DatabaseVersion; ++version) {
		dbExec(MigrationSQL[version]);
	}
	dbExec(SQL(COMMIT TRANSACTION;));
}

static inline void dbBackup(const char *path) {
	if (sqlite3_libversion_number() < 3027000) {
		errx(EX_CONFIG, "SQLite version 3.27.0 or newer required");
	}
	sqlite3_stmt *stmt = dbPrepare(SQL(VACUUM INTO :path;));
	dbBindText(stmt, ":path", path);
	dbRun(stmt);
	sqlite3_finalize(stmt);
}
