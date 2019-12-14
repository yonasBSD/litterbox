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
#include <sqlite3.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>

#include "database.h"

int main(int argc, char *argv[]) {
	char *path = NULL;
	bool init = false;
	bool migrate = false;

	int opt;
	while (0 < (opt = getopt(argc, argv, "d:im"))) {
		switch (opt) {
			break; case 'd': path = optarg;
			break; case 'i': init = true;
			break; case 'm': migrate = true;
			break; default:  return EX_USAGE;
		}
	}

	int flags = SQLITE_OPEN_READWRITE;
	if (init) flags |= SQLITE_OPEN_CREATE;

	sqlite3 *db = (path ? dbOpen(path, flags) : dbFind(flags));
	if (!db) errx(EX_NOINPUT, "database not found");

	if (init) {
		dbInit(db);
		return EX_OK;
	}
	if (migrate) {
		dbMigrate(db);
		return EX_OK;
	}

	if (dbVersion(db) != DatabaseVersion) {
		errx(EX_CONFIG, "database out of date; migrate with -m");
	}
}
