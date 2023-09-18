/* radare2 - MIT - Copyright 2022-2023 - pancake */

#include <stdio.h>
#include <stdbool.h>
#include "frida-core.h"
#include <r_util.h>
#include <r_util/r_print.h>

#ifdef _MSC_VER
#undef R2__WINDOWS__
#define R2__WINDOWS__ 1
#endif

static int on_compiler_diagnostics(void *user, GVariant *diagnostics) {
	gchar *str = g_variant_print (diagnostics, TRUE);
	str = r_str_replace (str, "int64", "", true);
	str = r_str_replace (str, "<", "", true);
	str = r_str_replace (str, ">", "", true);
	str = r_str_replace (str, "'", "\"", true);
	char *json = r_print_json_indent (str, true, "  ", NULL);
	eprintf ("%s\n", json);
	free (json);
	g_free (str);
	return 0;
}

static int show_help(const char *argv0, int line) {
	printf ("Usage: %s (-hSc) [-H foo.h] [-r root] [-o output.js] [path/to/file.{js,ts}] ...\n", argv0);
	if (!line) {
		printf (
		" -S                  Do not include source maps\n"
		" -c                  Enable compression\n"
		" -h                  Show this help message\n"
		" -H [file]           Output in C-friendly hexadecimal bytes\n"
		" -o [file]           Specify output file\n"
		" -r [project-root]   Specify the project root directory\n"
		" -q                  Be quiet\n"
		" -v                  Display version\n"
		);
	}
	return 1;
}

static char *to_header(const char *s) {
	RStrBuf *sb = r_strbuf_new ("");
	int count = 0;
	while (*s) {
		r_strbuf_appendf (sb, " 0x%02x,", 0xff & (*s));
		s++;
		count++;
		if (count > 0 && !(count % 8)) {
			r_strbuf_appendf (sb, "\n");
		}
	}
	r_strbuf_appendf (sb, " // fin\n");
	return r_strbuf_drain (sb);
}

int main(int argc, const char **argv) {
	const char *outfile = NULL;
	const char *arg0 = argv[0];
	int c, rc = 0;
	GCancellable *cancellable = NULL;
	GError *error = NULL;
	if (argc < 2) {
		return show_help (arg0, true);
	}
	bool quiet = false;
	const char *header = NULL;
	bool source_maps = true;
	bool compression = false;
	RGetopt opt;
	r_getopt_init (&opt, argc, argv, "r:SH:cho:qv");
	const char *proot = NULL;
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'r':
			proot = opt.arg;
			break;
		case 'H':
			header = opt.arg;
			break;
		case 'S':
			source_maps = false;
			break;
		case 'o':
			outfile = opt.arg;
			break;
		case 'c':
			compression = true;
			break;
		case 'q':
			quiet = true;
			break;
		case 'h':
			show_help (arg0, false);
			return 0;
		case 'v':
			if (quiet) {
				printf ("%s\n", R2FRIDA_VERSION_STRING);
			} else {
				printf ("r2frida: %s\n", R2FRIDA_VERSION_STRING);
				printf ("radare2: %s\n", R2_VERSION);
				printf ("frida: %s\n", FRIDA_VERSION_STRING);
			}
			return 0;
		default:
			return show_help (arg0, false);
		}
	}

	frida_init ();
	FridaDeviceManager *device_manager = frida_device_manager_new ();
	if (!device_manager) {
		R_LOG_ERROR ("Cannot open device manager");
		return 1;
	}
	FridaDevice *device = frida_device_manager_get_device_by_type_sync (device_manager, FRIDA_DEVICE_TYPE_LOCAL, 0, cancellable, &error);
	if (error || !device) {
		R_LOG_ERROR ("Cannot open local frida device");
		return 1;
	}
	char buf[1024];
	FridaCompiler *compiler = frida_compiler_new (device_manager);
	// g_signal_connect (compiler, "diagnostics", G_CALLBACK (on_compiler_diagnostics), rf);
	// FridaBuildOptions * fbo = frida_build_options_new ();
	FridaCompilerOptions *fco = frida_compiler_options_new ();
	if (!source_maps) {
		frida_compiler_options_set_source_maps (fco, FRIDA_SOURCE_MAPS_OMITTED);
	}
	if (compression) {
		frida_compiler_options_set_compression (fco, FRIDA_JS_COMPRESSION_TERSER);
	}
	//frida_compiler_options_set_project_root (fco, "../src/agent/"); // ".");

	int i;
	bool stdin_mode = false;
	if (argc - opt.ind > 1) {
		R_LOG_ERROR ("Only take one file as argument");
		return 1;
	}
	for (i = opt.ind; stdin_mode || i < argc; i = stdin_mode? i: i + 1) {
		char *filename = strdup (argv[i]);
		if (stdin_mode) {
			fflush (stdin);
			if (!fgets (buf, sizeof (buf), stdin)) {
				break;
			}
			buf[sizeof (buf) -1] = 0;
			free (filename);
			int len = strlen (buf);
			if (len > 0) {
				buf[len - 1] = 0;
			}
			filename = strdup (buf);
		} else {
			if (!strcmp (filename, "-")) {
				// enter stdin mode
				stdin_mode = true;
				continue;
			}
			if (!r_str_endswith (filename, ".js") && !r_str_endswith (filename, ".ts")) {
				R_LOG_ERROR ("The r2frida-compile only accepts .js and .ts files");
				return 1;
			}
		}
		if (R_STR_ISNOTEMPTY (proot)) {
			frida_compiler_options_set_project_root (fco, proot);
		}
#if 0
		// eprintf ("DEFAULT PROJECT ROOT %s\n", frida_compiler_options_get_project_root (fco));
		char *slash = strrchr (filename, '/');
		if (slash) {
			char *ofilename = filename;
			*slash = 0;
			char *root = strdup (filename);
			filename = strdup (slash + 1);
			// char *d = r_file_abspath (root);
			char *d = strdup ("/Users/pancake/prg/r2frida/"); // r_file_abspath (root);
			frida_compiler_options_set_project_root (fco, d);
			eprintf ("PROJECT ROOT IS (%s)\n", d);
			free (d);
			free (root);
			free (ofilename);
		}
#endif
		g_signal_connect (compiler, "diagnostics", G_CALLBACK (on_compiler_diagnostics), NULL);
		char *slurpedData = frida_compiler_build_sync (compiler, filename, FRIDA_BUILD_OPTIONS (fco), NULL, &error);
		if (error || !slurpedData) {
			R_LOG_ERROR ("%s", error->message);
			rc = 1;
		} else {
			if (outfile) {
#if R2__WINDOWS__
eprintf ("Using windows dump\n");
				HANDLE fh = CreateFile (outfile,
					GENERIC_WRITE,
					0, NULL, CREATE_ALWAYS,
					FILE_ATTRIBUTE_NORMAL, NULL);
				if (fh == INVALID_HANDLE_VALUE) {
					R_LOG_ERROR ("Cannot dump to %s", outfile);
					rc = 1;
				} else {
					DWORD written = 0;
eprintf ("Writing file %s\n", outfile);
					BOOL res = WriteFile (fh, slurpedData, strlen (slurpedData), &written, NULL);
					if (res == FALSE) {
						R_LOG_ERROR ("Cannot write to %s", outfile);
						rc = 1;
					} else {
						rc = 0;
					}
eprintf ("Closing handl\n");
					CloseHandle (fh);
				}
#else
				if (!r_file_dump (outfile, (const ut8*)slurpedData, -1, false)) {
					R_LOG_ERROR ("Cannot dump to %s", outfile);
					rc = 1;
				}
#endif
			} else {
				printf ("%s\n", slurpedData);
			}
			if (header) {
				char *ns = to_header (slurpedData);
				if (!r_file_dump (header, (const ut8*)ns, -1, false)) {
					R_LOG_ERROR ("Cannot dump to %s", header);
					rc = 1;
				}
				free (ns);
			}
		}
		free (slurpedData);
		free (filename);
		if (rc && stdin_mode) {
			break;
		}
	}
	g_object_unref (compiler);
	g_object_unref (device_manager);
	return rc;
}
