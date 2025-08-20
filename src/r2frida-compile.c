/* radare2 - MIT - Copyright 2022-2025 - pancake */

#include <stdio.h>
#include <stdbool.h>
#include "frida-core.h"
#include <r_util.h>
#include <r_util/r_print.h>
#include "../config.h"
#include "esmtool.inc.c"

#ifdef _MSC_VER
#undef R2__WINDOWS__
#define R2__WINDOWS__ 1
#endif

// Shared diagnostics for Frida compiler
#include "diagnostics.h"

extern int pkgmgr_search(const char *registry, const char *query, gboolean json_output, int offset, int limit);
extern int pkgmgr_install(const char *registry, char **specs, int nspecs, const char *project_root, gboolean save_dev, gboolean save_prod, gboolean save_optional, char **omits, gboolean quiet);

static bool compile_show_json = false;

// diagnostics helpers live in diagnostics.c

static int on_compiler_diagnostics(void *user, GVariant *diagnostics) {
	r2f_on_compiler_diagnostics (user, diagnostics);
	return 0;
}

static int show_help(const char *argv0, int line) {
	printf ("Usage: %s (-hSc) [[-p|-u] js dir] | [-H foo.h] [-r root] [-o output.js] [file.{js,ts}] ...\n", argv0);
	if (!line) {
		printf (
		" -B [esm|iife]       desired bundle format (default is `esm`)\n"
		" -c                  Enable compression\n"
		" -h                  Show this help message\n"
		" -H [file]           Output in C-friendly hexadecimal bytes\n"
		" -o [file]           Specify output file\n"
		" -p [esmjs] [dir]    Pack directory contents into an esmjs file\n"
		" -q                  Be quiet\n"
		" -r [project-root]   Specify the project root directory (used by -i)\n"
		" -S                  Do not include source maps\n"
		" -T [full|none]      desired type-checking mode (default is full)\n"
		" -u [esmjs] [dir]    Unpack ESM into the given directory\n"
		" -j                  Use JSON format for error logs\n"
		" -s [query]          Search packages in the Frida registry\n"
		" -i                  Install package(s) listed in package.json\n"
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
	GError *error = NULL;
	if (argc < 2) {
		return show_help (arg0, true);
	}
	bool quiet = false;
	const char *header = NULL;
	const char *type_check = NULL;
	const char *bundle_format = NULL;
	bool source_maps = true;
	bool compression = false;
	bool pack = false;
	bool unpack = false;
	RGetopt opt;
	r_getopt_init (&opt, argc, argv, "r:SH:cho:qvp:u:T:B:jis:");
	const char *proot = NULL;
	bool do_search = false;
	const char *search_query = NULL;
	bool do_install = false;
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'r':
			proot = opt.arg;
			break;
		case 'H':
			header = opt.arg;
			break;
		case 'B':
			bundle_format = opt.arg;
			break;
		case 'T':
			type_check = opt.arg;
			break;
		case 'S':
			source_maps = false;
			break;
		case 'p':
			pack = true;
			break;
		case 'u':
			unpack = true;
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
		case 'j':
			compile_show_json = true;
			break;
		case 'i':
			do_install = true;
			break;
		case 's':
			do_search = true;
			search_query = opt.arg;
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
	if (pack || unpack) {
		if (opt.ind >= argc) {
			R_LOG_ERROR ("Usage: r2frida-compile [-p|-u] [esmjs] [directory]");
			return 1;
		}
		const char *arg0 = opt.arg;
		const char *arg1 = argv[opt.ind];
		if (!esmtool (pack, arg0, arg1)) {
			return 1;
		}
		return 0;
	}

	frida_init ();
	if (do_search) {
		return pkgmgr_search(NULL, search_query, compile_show_json, -1, -1);
	}
	if (do_install) {
		int nspec = argc - opt.ind;
		char **specs = NULL;
		if (nspec > 0) specs = (char**)&argv[opt.ind];
		return pkgmgr_install(NULL, specs, nspec, proot, false, false, false, NULL, quiet);
	}
	FridaDeviceManager *device_manager = NULL;
#if FRIDA_VERSION_MAJOR < 17
	GCancellable *cancellable = NULL;
	device_manager = frida_device_manager_new ();
	if (!device_manager) {
		R_LOG_ERROR ("Cannot open device manager");
		return 1;
	}
	FridaDevice *device = frida_device_manager_get_device_by_type_sync (device_manager, FRIDA_DEVICE_TYPE_LOCAL, 0, cancellable, &error);
	if (error || !device) {
		R_LOG_ERROR ("Cannot open local frida device");
		return 1;
	}
#else
	/* On Frida >= 17.1.0 frida-compiler accepts null */
	device_manager = NULL;
#endif
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
#if FRIDA_VERSION_MAJOR >= 17
	if (type_check) {
		int mode;
		if (!strcmp (type_check, "full")) {
			mode = FRIDA_TYPE_CHECK_MODE_FULL;
		} else if (!strcmp (type_check, "none")) {
			mode = FRIDA_TYPE_CHECK_MODE_NONE;
		} else {
			R_LOG_ERROR ("Invalid option for -T, expected argument 'full' or 'none'");
			return 1;
		}
		frida_compiler_options_set_type_check (fco, mode);
	}
	if (bundle_format) {
		int mode;
		if (!strcmp (bundle_format, "esm")) {
			mode = FRIDA_BUNDLE_FORMAT_ESM;
		} else if (!strcmp (bundle_format, "iife")) {
			mode = FRIDA_BUNDLE_FORMAT_IIFE;
		} else {
			R_LOG_ERROR ("Invalid option for -B, expected argument 'full' or 'none'");
			return 1;
		}
		frida_compiler_options_set_bundle_format (fco, mode);
	}
#else
	if (type_check) {
		R_LOG_WARN ("The -T option requires Frida17 at least");
	}
	if (bundle_format) {
		R_LOG_WARN ("The -B option requires Frida17 at least");
	}
	if (type_check || bundle_format) {
		return 1;
	}
#endif

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
			buf[sizeof (buf) - 1] = 0;
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
#if 0
		} else {
			char *absroot = r_sys_getdir ();
			if (R_STR_ISNOTEMPTY (absroot)) {
				frida_compiler_options_set_project_root (fco, absroot);
			}
			free (absroot);
#endif
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
			R2FDiagOptions diag_opts = { .json = compile_show_json };
			g_signal_connect (compiler, "diagnostics", G_CALLBACK (on_compiler_diagnostics), &diag_opts);
		char *slurpedData = frida_compiler_build_sync (compiler, filename, FRIDA_BUILD_OPTIONS (fco), NULL, &error);
		if (error || !slurpedData) {
			R_LOG_ERROR ("%s", error->message);
			rc = 1;
		} else {
			if (outfile) {
#if R2__WINDOWS__
				HANDLE fh = CreateFile (outfile,
					GENERIC_WRITE,
					0, NULL, CREATE_ALWAYS,
					FILE_ATTRIBUTE_NORMAL, NULL);
				if (fh == INVALID_HANDLE_VALUE) {
					R_LOG_ERROR ("Cannot dump to %s", outfile);
					rc = 1;
				} else {
					DWORD written = 0;
					BOOL res = WriteFile (fh, slurpedData, strlen (slurpedData), &written, NULL);
					if (res == FALSE) {
						R_LOG_ERROR ("Cannot write to %s", outfile);
						rc = 1;
					} else {
						rc = 0;
					}
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
#if FRIDA_VERSION_MAJOR < 17
	g_object_unref (device_manager);
#endif
	return rc;
}
