/* radare2 - MIT - Copyright 2022-2025 - pancake */

#include <r_util.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HEADER "\xF0\x9F\x93\xA6\n"

static bool write_file(FILE *out, const char *path, const char *root) {
	int usz;
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

static bool unpack(const char *infile, const char *outdir) {
	FILE *in = fopen (infile, "rb");
	if (!in) {
		R_LOG_ERROR ("Cannot open input file %s", infile);
		return false;
	}

	char line[4096];
	if (!fgets (line, sizeof (line), in)) {
		fclose (in);
		return false;
	}
	if (strcmp (line, HEADER) != 0) {
		R_LOG_ERROR ("Invalid ESM archive header");
		fclose (in);
		return false;
	}

	while (fgets (line, sizeof (line), in)) {
		// Skip empty lines
		if (line[0] == '\n' || line[0] == '\0') {
			continue;
		}

		char *sep = strchr (line, ' ');
		if (!sep || sep[1] != '/') {
			continue;
		}

		*sep = '\0';
		size_t size = (size_t)strtoul (line, NULL, 10);
		char *filename = sep + 2; // Skip space and forward slash

		// Trim newline from filename
		char *newline = strchr (filename, '\n');
		if (newline) {
			*newline = '\0';
		}

		// Create full output path with platform-appropriate separators
		char *platform_filename = r_str_replace (strdup (filename), "/", R_SYS_DIR, true);
		if (!platform_filename) {
			// Skip the file content and newline
			fseek (in, size + 1, SEEK_CUR);
			continue;
		}
		char *fullpath = r_str_newf ("%s%s%s", outdir, R_SYS_DIR, platform_filename);
		if (!fullpath) {
			free (platform_filename);
			// Skip the file content and newline
			fseek (in, size + 1, SEEK_CUR);
			continue;
		}

		char *dirname = r_file_dirname (fullpath);
		if (!r_sys_mkdirp (dirname)) {
			R_LOG_ERROR ("Cannot create directory for %s", fullpath);
			free (dirname);
			free (platform_filename);
			free (fullpath);
			// Skip the file content and newline
			fseek (in, size + 1, SEEK_CUR);
			continue;
		}
		free (dirname);

		// Read and write file content
		if (size > 0) {
			ut8 *buffer = malloc (size);
			if (buffer) {
				size_t bytes_read = fread (buffer, 1, size, in);
				if (bytes_read == size) {
					if (!r_file_dump (fullpath, buffer, size, false)) {
						R_LOG_ERROR ("Cannot write file %s", fullpath);
					}
				} else {
					R_LOG_ERROR ("Could not read expected %zu bytes for %s, got %zu", size, fullpath, bytes_read);
				}
				free (buffer);
			} else {
				R_LOG_ERROR ("Cannot allocate buffer for %s", fullpath);
			}
		}

		// Skip the newline after file content
		const int ch = fgetc (in);
		if (ch && (ch != '\n' || ch == '\r')) {
			R_LOG_INFO ("Expected newline at the end of the file for %s", fullpath);
		}

		free (platform_filename);
		free (fullpath);
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
