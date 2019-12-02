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

#define DATABASE_PATH "litterbox/database.sqlite"

static inline sqlite3 *dbOpenPath(char *path, int flags) {
	char *base = strrchr(path, '/');
	if (flags & SQLITE_OPEN_CREATE && base) {
		*base = '\0';
		int error = mkdir(path, 0700);
		if (error && errno != EEXIST) err(EX_CANTCREAT, "%s", path);
		*base = '/';
	}
	sqlite3 *db;
	int error = sqlite3_open_v2(path, &db, flags, NULL);
	if (!error) return db;
	if (error == SQLITE_CANTOPEN) {
		sqlite3_close(db);
		return NULL;
	}
	errx(EX_NOINPUT, "%s: %s", path, sqlite3_errmsg(db));
}

static inline sqlite3 *dbOpen(int flags) {
	const char *home = getenv("HOME");
	const char *dataHome = getenv("XDG_DATA_HOME");
	const char *dataDirs = getenv("XDG_DATA_DIRS");
	char path[PATH_MAX];
	if (dataHome) {
		snprintf(path, sizeof(path), "%s/" DATABASE_PATH, dataHome);
	} else {
		snprintf(path, sizeof(path), "%s/.local/share/" DATABASE_PATH, home);
	}
	sqlite3 *db = dbOpenPath(path, flags);
	if (db) return db;
	while (dataDirs && *dataDirs) {
		size_t len = strcspn(dataDirs, ":");
		snprintf(path, sizeof(path), "%.*s/" DATABASE_PATH, (int)len, dataDirs);
		db = dbOpenPath(path, flags);
		if (db) return db;
		dataDirs += len;
		if (*dataDirs) dataDirs++;
	}
	return NULL;
}
