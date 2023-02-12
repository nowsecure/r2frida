/* radare2 - MIT - Copyright 2022-2023 - pancake */

#include <stdio.h>
#include <stdbool.h>
#include "frida-core.h"
#include <r_util.h>
#include <r_util/r_print.h>


static int on_compiler_diagnostics(void *user, GVariant *diagnostics) {
	gchar *str = g_variant_print (diagnostics, TRUE);
	str = r_str_replace (str, "int64", "int64:", true);
	char *json = r_print_json_indent (str, true, "  ", NULL);
	eprintf ("%s\n", json);
	free (json);
	g_free (str);
	return 0;
}

int main(int argc, char **argv) {
	int rc = 0;
	GCancellable *cancellable = NULL;
	GError *error = NULL;
	const char *filename = "index.ts";
	if (argc < 2) {
		eprintf ("Usage: frida-compile [-] [file.{js,ts}] ...\n");
		return 1;
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
	frida_compiler_options_set_source_maps (fco, FRIDA_SOURCE_MAPS_OMITTED);
	frida_compiler_options_set_compression (fco, FRIDA_JS_COMPRESSION_TERSER);
	//frida_compiler_options_set_project_root (fco, "../src/agent/"); // ".");

	int i;
	bool stdin_mode = false;
	for (i = 1; stdin_mode || i < argc; i = stdin_mode? i: i+1) {
		char *filename = strdup (argv[i]);
		if (stdin_mode) {
			fflush (stdin);
			fgets (buf, sizeof (buf), stdin);
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
		}
#if 0
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
			eprintf ("ERROR: %s\n", error->message);
			rc = 1;
		} else {
			printf ("%s\n", slurpedData);
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
