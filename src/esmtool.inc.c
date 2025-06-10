/* radare2 - MIT - Copyright 2022-2025 - pancake */

#include <r_util.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <libgen.h>

#define HEADER "\xF0\x9F\x93\xA6\n"
#define MAX_PATH 4096

static bool write_file(FILE *out, const char *path, const char *root) {
	FILE *in = fopen (path, "rb");
	if (!in) {
		return false;
	}

	fseek (in, 0, SEEK_END);
	long size = ftell (in);
	fseek (in, 0, SEEK_SET);

	char relpath[MAX_PATH];
	snprintf (relpath, sizeof (relpath), "%s", path + strlen (root) + 1);

	fprintf (out, "%ld /%s\n", size, relpath);
	long i;
	for (i = 0; i < size; i++) {
		fputc (fgetc (in), out);
	}
	fputc ('\n', out);

	fclose (in);
	return true;
}

static bool walk_dir(FILE *out, const char *dir, const char *root) {
	bool res = true;
	DIR *d = opendir (dir);
	if (!d) {
		return false;
	}
	struct dirent *entry;
	while ((entry = readdir (d))) {
		if (!strcmp (entry->d_name, ".") || !strcmp (entry->d_name, "..")) {
			continue;
		}

		char path[MAX_PATH];
		snprintf (path, sizeof (path), "%s/%s", dir, entry->d_name);

		struct stat st;
		if (stat (path, &st) == -1) {
			continue;
		}

		if (S_ISDIR (st.st_mode)) {
			if (!walk_dir (out, path, root)) {
				R_LOG_ERROR ("Cannot walk into %s", path);
				res = false;
			}
		} else if (S_ISREG(st.st_mode)) {
			if (!write_file (out, path, root)) {
				R_LOG_ERROR ("Cannot write into %s", path);
				res = false;
			}
		}
	}
	closedir (d);
	return res;
}

static bool pack(const char *outfile, const char *indir) {
	FILE *out = fopen (outfile, "wb");
	if (!out) {
		perror ("fopen");
		return false;
	}
	fputs (HEADER, out);
	bool res = walk_dir (out, indir, indir);
	fclose (out);
	return res;
}

static bool ensure_parent_dir(const char *path) {
	char tmp[MAX_PATH];
	snprintf (tmp, sizeof (tmp), "%s", path);
	char *dir = dirname (tmp);
	if (!dir) {
		return false;
	}
	char buf[MAX_PATH];
	snprintf (buf, sizeof (buf), "%s", dir);
	for (char *p = buf + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			mkdir (buf, 0755);
			*p = '/';
		}
	}
	mkdir (buf, 0755);
	return true;
}

bool unpack(const char *infile, const char *outdir) {
	FILE *in = fopen (infile, "rb");
	if (!in) {
		perror ("fopen");
		return false;
	}

	char line[MAX_PATH];
	if (!fgets (line, sizeof (line), in)) {
		return false;
	}

	while (fgets (line, sizeof (line), in)) {
		char *sep = strchr (line, ' ');
		if (!sep || sep[1] != '/') {
			continue;
		}

		*sep = '\0';
		long size = strtol (line, NULL, 10);
		char *filename = sep + 1;

		// Trim newline from filename
		char *newline = strchr (filename, '\n');
		if (newline) {
			*newline = '\0';
		}

		char fullpath[MAX_PATH];
		snprintf (fullpath, sizeof (fullpath), "%s/%s", outdir, filename);
		if (!ensure_parent_dir (fullpath)) {
			R_LOG_ERROR ("Cannot ensure parent dir");
			break;
		}

		FILE *out = fopen (fullpath, "wb");
		if (!out) {
			continue;
		}

		for (long i = 0; i < size; ++i) {
			int c = fgetc (in);
			if (c == EOF) {
				break;
			}
			fputc (c, out);
		}
		fgetc (in); // skip newline
		fclose (out);
	}
	fclose (in);
	return true;
}

static bool esmtool(bool dopack, const char *fil, const char *dirnam) {
	if (dopack) {
		return pack (fil, dirnam);
	}
	return unpack (fil, dirnam);
}
