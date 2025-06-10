#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <libgen.h>

#define HEADER "\xF0\x9F\x93\xA6\n"
#define MAX_PATH 4096

void write_file(FILE *out, const char *path, const char *root) {
	FILE *in = fopen(path, "rb");
	if (!in) return;

	fseek(in, 0, SEEK_END);
	long size = ftell(in);
	fseek(in, 0, SEEK_SET);

	char relpath[MAX_PATH];
	snprintf(relpath, sizeof(relpath), "%s", path + strlen(root) + 1);

	fprintf(out, "%ld /%s\n", size, relpath);
	for (long i = 0; i < size; ++i)
		fputc(fgetc(in), out);
	fputc('\n', out);

	fclose(in);
}

void walk_dir(FILE *out, const char *dir, const char *root) {
	DIR *d = opendir(dir);
	if (!d) return;
	struct dirent *entry;
	while ((entry = readdir(d))) {
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
			continue;

		char path[MAX_PATH];
		snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name);

		struct stat st;
		if (stat(path, &st) == -1) continue;

		if (S_ISDIR(st.st_mode)) {
			walk_dir(out, path, root);
		} else if (S_ISREG(st.st_mode)) {
			write_file(out, path, root);
		}
	}
	closedir(d);
}

void pack(const char *outfile, const char *indir) {
	FILE *out = fopen(outfile, "wb");
	if (!out) {
		perror("fopen");
		return;
	}
	fputs(HEADER, out);
	walk_dir(out, indir, indir);
	fclose(out);
}

void ensure_parent_dir(const char *path) {
	char tmp[MAX_PATH];
	snprintf(tmp, sizeof(tmp), "%s", path);
	char *dir = dirname(tmp);
	char buf[MAX_PATH];
	snprintf(buf, sizeof(buf), "%s", dir);
	for (char *p = buf + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			mkdir(buf, 0755);
			*p = '/';
		}
	}
	mkdir(buf, 0755);
}

bool unpack(const char *infile, const char *outdir) {
	FILE *in = fopen(infile, "rb");
	if (!in) {
		perror("fopen");
		return false;
	}

	char line[MAX_PATH];
	if (!fgets(line, sizeof(line), in)) return; // skip header

	while (fgets(line, sizeof(line), in)) {
		char *sep = strchr(line, ' ');
		if (!sep || sep[1] != '/') continue;

		*sep = '\0';
		long size = strtol(line, NULL, 10);
		char *filename = sep + 1;

		// Trim newline from filename
		char *newline = strchr(filename, '\n');
		if (newline) *newline = '\0';

		char fullpath[MAX_PATH];
		snprintf(fullpath, sizeof(fullpath), "%s/%s", outdir, filename);
		ensure_parent_dir(fullpath);

		FILE *out = fopen(fullpath, "wb");
		if (!out) continue;

		for (long i = 0; i < size; ++i) {
			int c = fgetc(in);
			if (c == EOF) break;
			fputc(c, out);
		}
		fgetc(in); // skip newline
		fclose(out);
	}
	fclose(in);
	return true;
}

static bool esmtool(bool dopack, const char *fil, const char *dirnam) {
	if (dopack) {
		return pack (fil, dirnam);
	}
	return unpack (fil, dirnam);
}

#if USEMAIN
int main(int argc, char **argv) {
	if (argc != 4) {
		fprintf(stderr, "Usage: %s -p|-u file.js dir\n", argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "-p") == 0) {
		pack(argv[2], argv[3]);
	} else if (strcmp(argv[1], "-u") == 0) {
		unpack(argv[2], argv[3]);
	} else {
		fprintf(stderr, "Unknown option: %s\n", argv[1]);
		return 1;
	}
	return 0;
}

#endif
