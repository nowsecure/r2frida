/* radare2 - MIT - Copyright 2022-2025 - pancake */

#include <r_util.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HEADER "\xF0\x9F\x93\xA6\n"
#define BODY_SEPARATOR "\xE2\x9C\x84\n"

#ifndef ESMTOOL_ENABLE_PACK
#define ESMTOOL_ENABLE_PACK 1
#endif

static R_UNUSED char *esmarchive_first_entry(const char *filename) {
	FILE *in = fopen (filename, "rb");
	if (!in) {
		return NULL;
	}
	char line[4096];
	if (!fgets (line, sizeof (line), in) || strcmp (line, HEADER)) {
		fclose (in);
		return NULL;
	}
	char *result = NULL;
	while (fgets (line, sizeof (line), in)) {
		char *sep = strchr (line, ' ');
		if (sep && sep[1] == '/') {
			char *path = sep + 2;
			r_str_trim_tail (path);
			result = r_str_replace (strdup (path), "/", R_SYS_DIR, true);
			break;
		}
	}
	fclose (in);
	return result;
}

static bool esmarchive_extract(FILE *in, const char *outdir, const char *name, size_t size) {
	char *pfn = r_str_replace (strdup (name), "/", R_SYS_DIR, true);
	if (!pfn) {
		return false;
	}
	char *fullpath = r_str_newf ("%s%s%s", outdir, R_SYS_DIR, pfn);
	free (pfn);
	if (!fullpath) {
		return false;
	}
	char *dir = r_file_dirname (fullpath);
	if (dir) {
		r_sys_mkdirp (dir);
		free (dir);
	}
	bool ok = true;
	if (size > 0) {
		ut8 *buf = malloc (size);
		if (buf) {
			ok = (fread (buf, 1, size, in) == size)
				&& r_file_dump (fullpath, buf, size, false);
			free (buf);
		} else {
			ok = false;
		}
	}
	free (fullpath);
	return ok;
}

static bool esmarchive_unpack(const char *infile, const char *outdir) {
	FILE *in = fopen (infile, "rb");
	if (!in) {
		R_LOG_ERROR ("Cannot open input file %s", infile);
		return false;
	}
	char line[4096];
	if (!fgets (line, sizeof (line), in) || strcmp (line, HEADER) != 0) {
		R_LOG_ERROR ("Invalid ESM archive header");
		fclose (in);
		return false;
	}
	// read entry headers until separator or end
	size_t sizes[256];
	char *names[256];
	int count = 0;
	bool has_toc = false;
	const long after_header = ftell (in);
	while (count < 256 && fgets (line, sizeof (line), in)) {
		if (!strcmp (line, BODY_SEPARATOR)) {
			has_toc = true;
			break;
		}
		if (line[0] == '\n' || line[0] == '\0') {
			continue;
		}
		char *sep = strchr (line, ' ');
		if (!sep || sep[1] != '/') {
			break;
		}
		*sep = '\0';
		sizes[count] = (size_t)strtoul (line, NULL, 10);
		char *name = sep + 2;
		r_str_trim_tail (name);
		names[count] = strdup (name);
		count++;
	}
	bool ok = true;
	int i;
	if (has_toc) {
		for (i = 0; i < count; i++) {
			ok &= esmarchive_extract (in, outdir, names[i], sizes[i]);
			if (i < count - 1) {
				while (fgets (line, sizeof (line), in)) {
					if (!strcmp (line, BODY_SEPARATOR)) {
						break;
					}
				}
			}
		}
	} else {
		// legacy: content follows each header inline
		fseek (in, after_header, SEEK_SET);
		for (i = 0; i < count; i++) {
			if (!fgets (line, sizeof (line), in)) {
				ok = false;
				break;
			}
			ok &= esmarchive_extract (in, outdir, names[i], sizes[i]);
			if (fgetc (in) == EOF) {
				ok = false;
				break;
			}
		}
	}
	for (i = 0; i < count; i++) {
		free (names[i]);
	}
	fclose (in);
	return ok;
}

#if ESMTOOL_ENABLE_PACK
static bool write_file(FILE *out, const char *path, const char *root) {
	size_t usz;
	char *content = r_file_slurp (path, &usz);
	if (!content) {
		return false;
	}

	size_t size = (size_t)usz;

	// Get relative path
	const char *relpath = path + strlen (root);
	if (*relpath == R_SYS_DIR[0]) {
		relpath++;
	}

	// Normalize path separators to forward slashes for archive format
	char *normalized_path = r_str_replace (strdup (relpath), R_SYS_DIR, "/", true);
	if (!normalized_path) {
		free (content);
		return false;
	}

	fprintf (out, "%zu /%s\n", size, normalized_path);
	fwrite (content, 1, size, out);
	fputc ('\n', out);

	free (content);
	free (normalized_path);
	return true;
}

static bool walk_dir(FILE *out, const char *dir, const char *root) {
	bool res = true;
	RList *files = r_sys_dir (dir);
	if (!files) {
		return false;
	}

	RListIter *iter;
	char *entry;
	r_list_foreach (files, iter, entry) {
		if (!strcmp (entry, ".") || !strcmp (entry, "..")) {
			continue;
		}

		char *path = r_str_newf ("%s%s%s", dir, R_SYS_DIR, entry);
		if (!path) {
			res = false;
			continue;
		}

		if (r_file_is_directory (path)) {
			if (!walk_dir (out, path, root)) {
				R_LOG_ERROR ("Cannot walk into %s", path);
				res = false;
			}
		} else if (r_file_exists (path)) {
			if (!write_file (out, path, root)) {
				R_LOG_ERROR ("Cannot write file %s", path);
				res = false;
			}
		}
		free (path);
	}
	r_list_free (files);
	return res;
}

static bool pack(const char *outfile, const char *indir) {
	FILE *out = fopen (outfile, "wb");
	if (!out) {
		R_LOG_ERROR ("Cannot open output file %s", outfile);
		return false;
	}
	fputs (HEADER, out);
	bool res = walk_dir (out, indir, indir);
	fclose (out);
	return res;
}

static bool esmtool(bool dopack, const char *fil, const char *dirnam) {
	if (dopack) {
		return pack (fil, dirnam);
	}
	return esmarchive_unpack (fil, dirnam);
}
#endif
