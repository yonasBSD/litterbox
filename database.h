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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sysexits.h>

#define DATABASE_PATH "litterbox/litterbox.sqlite"

enum { DatabaseVersion = 0 };

enum Type {
	Privmsg,
	Notice,
	Join,
	Part,
	Kick,
	Quit,
	Nick,
	Topic,
};

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

	error = sqlite3_exec(db, "PRAGMA foreign_keys = true;", NULL, NULL, NULL);
	if (error) errx(EX_SOFTWARE, "sqlite3_exec: %s", sqlite3_errmsg(db));

	return db;
}

static inline sqlite3 *dbFind(int flags) {
	const char *home = getenv("HOME");
	const char *dataHome = getenv("XDG_DATA_HOME");
	const char *dataDirs = getenv("XDG_DATA_DIRS");

	char path[PATH_MAX];
	if (dataHome) {
		snprintf(path, sizeof(path), "%s/" DATABASE_PATH, dataHome);
	} else {
		if (!home) errx(EX_CONFIG, "HOME unset");
		snprintf(path, sizeof(path), "%s/.local/share/" DATABASE_PATH, home);
	}
	sqlite3 *db = dbOpen(path, flags);
	if (db) return db;

	if (!dataDirs) dataDirs = "/usr/local/share:/usr/share";
	while (*dataDirs) {
		size_t len = strcspn(dataDirs, ":");
		snprintf(path, sizeof(path), "%.*s/" DATABASE_PATH, (int)len, dataDirs);
		db = dbOpen(path, flags);
		if (db) return db;
		dataDirs += len;
		if (*dataDirs) dataDirs++;
	}
	return NULL;
}

static inline int dbVersion(sqlite3 *db) {
	sqlite3_stmt *stmt;
	int error = sqlite3_prepare_v2(db, "PRAGMA user_version;", -1, &stmt, NULL);
	if (error) errx(EX_SOFTWARE, "sqlite3_prepare_v2: %s", sqlite3_errmsg(db));

	error = sqlite3_step(stmt);
	if (error != SQLITE_ROW) {
		errx(EX_SOFTWARE, "sqlite3_step: %s", sqlite3_errmsg(db));
	}
	int version = sqlite3_column_int(stmt, 0);

	sqlite3_finalize(stmt);
	return version;
}

static const char *InitSQL = {
	"BEGIN TRANSACTION;"
	"CREATE TABLE networks ("
		"id INTEGER PRIMARY KEY,"
		"name TEXT NOT NULL UNIQUE"
	");"
	"CREATE TABLE contexts ("
		"id INTEGER PRIMARY KEY,"
		"networkID INTEGER NOT NULL REFERENCES networks,"
		"name TEXT NOT NULL,"
		"query BOOLEAN NOT NULL,"
		"UNIQUE (networkID, name)"
	");"
	"CREATE TABLE names ("
		"id INTEGER PRIMARY KEY,"
		"nick TEXT NOT NULL,"
		"user TEXT NOT NULL,"
		"host TEXT NOT NULL,"
		"UNIQUE (nick, user, host)"
	");"
	"CREATE TABLE events ("
		"id INTEGER PRIMARY KEY,"
		"time DATETIME NOT NULL,"
		"type INTEGER NOT NULL,"
		"contextID INTEGER NOT NULL REFERENCES contexts,"
		"nameID INTEGER NOT NULL REFERENCES names,"
		"target TEXT,"
		"message TEXT"
	");"
	// TODO: Create other indexes on events?
	"CREATE VIRTUAL TABLE search USING fts5 ("
		"message,"
		"content = events,"
		"content_rowid = id,"
		"tokenize = 'porter'"
	");"
	"CREATE TRIGGER eventsInsert AFTER INSERT ON events BEGIN"
	" INSERT INTO search (rowid, message) VALUES (new.id, new.message);"
	"END;"
	"COMMIT TRANSACTION;"
};

static inline void dbInit(sqlite3 *db) {
	int error = sqlite3_exec(db, InitSQL, NULL, NULL, NULL);
	if (error) errx(EX_SOFTWARE, "sqlite3_exec: %s", sqlite3_errmsg(db));
}

static const char *MigrationSQL[] = {
	NULL,
};

static inline void dbMigrate(sqlite3 *db) {
	for (int version = dbVersion(db); version < DatabaseVersion; ++version) {
		int error = sqlite3_exec(db, MigrationSQL[version], NULL, NULL, NULL);
		if (error) errx(EX_SOFTWARE, "sqlite3_exec: %s", sqlite3_errmsg(db));
	}
}
