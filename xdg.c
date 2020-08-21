/* Copyright (C) 2019, 2020  C. McEnroe <june@causal.agency>
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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define SUBDIR "litterbox"

struct Base {
	const char *envHome;
	const char *envDirs;
	const char *defHome;
	const char *defDirs;
};

static const struct Base Config = {
	.envHome = "XDG_CONFIG_HOME",
	.envDirs = "XDG_CONFIG_DIRS",
	.defHome = ".config",
	.defDirs = "/etc/xdg",
};

static const struct Base Data = {
	.envHome = "XDG_DATA_HOME",
	.envDirs = "XDG_DATA_DIRS",
	.defHome = ".local/share",
	.defDirs = "/usr/local/share:/usr/share",
};

static const char *basePath(
	struct Base base,
	char *buf, size_t cap, const char **dirs, const char *path
) {
	if (*dirs) {
		if (!**dirs) return NULL;
		size_t len = strcspn(*dirs, ":");
		snprintf(buf, cap, "%.*s/" SUBDIR "/%s", (int)len, *dirs, path);
		*dirs += len;
		if (**dirs) *dirs += 1;
		return buf;
	}

	if (path[0] == '/' || path[0] == '.') {
		*dirs = "";
		return path;
	}

	*dirs = getenv(base.envDirs);
	if (!*dirs) *dirs = base.defDirs;

	const char *home = getenv("HOME");
	const char *baseHome = getenv(base.envHome);
	if (baseHome) {
		snprintf(buf, cap, "%s/" SUBDIR "/%s", baseHome, path);
	} else {
		if (!home) return NULL;
		snprintf(buf, cap, "%s/%s/" SUBDIR "/%s", home, base.defHome, path);
	}
	return buf;
}

const char *
configPath(char *buf, size_t cap, const char **dirs, const char *path) {
	return basePath(Config, buf, cap, dirs, path);
}

const char *
dataPath(char *buf, size_t cap, const char **dirs, const char *path) {
	return basePath(Data, buf, cap, dirs, path);
}

FILE *configOpen(const char *path, const char *mode) {
	const char *abs;
	char buf[PATH_MAX];
	const char *dirs = NULL;
	while (NULL != (abs = configPath(buf, sizeof(buf), &dirs, path))) {
		FILE *file = fopen(abs, mode);
		if (file) return file;
		if (errno != ENOENT) warn("%s", abs);
	}
	FILE *file = fopen(path, mode);
	if (!file) warn("%s", path);
	return file;
}

void dataMkdir(const char *path) {
	char buf[PATH_MAX];
	const char *dirs = NULL;
	const char *abs = dataPath(buf, sizeof(buf), &dirs, path);
	int error = mkdir(abs, S_IRWXU);
	if (error && errno != EEXIST) warn("%s", abs);
}

FILE *dataOpen(const char *path, const char *mode) {
	const char *abs;
	char buf[PATH_MAX];
	const char *dirs = NULL;
	while (NULL != (abs = dataPath(buf, sizeof(buf), &dirs, path))) {
		FILE *file = fopen(abs, mode);
		if (file) return file;
		if (errno != ENOENT) warn("%s", abs);
	}

	if (mode[0] != 'r') {
		dirs = NULL;
		abs = dataPath(buf, sizeof(buf), &dirs, path);
		if (!abs) return NULL;

		dataMkdir("");
		FILE *file = fopen(abs, mode);
		if (!file) warn("%s", abs);
		return file;
	}

	FILE *file = fopen(path, mode);
	if (!file) warn("%s", path);
	return file;
}
