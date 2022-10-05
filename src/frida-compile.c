#include <stdio.h>
#include <stdbool.h>
#include "frida-core.h"

static int on_compiler_diagnostics (void) {
	printf ("DIAGNOSTICS!\n");
	return 0;
}

int main(int argc, char **argv) {
	GCancellable *cancellable = NULL;
	GError *error = NULL;
	const char *filename = "index.ts";
	if (argc < 2) {
		printf ("Usage: frida-compile [-] [file.{js,ts}] ...\n");
		return 1;
	}

	frida_init ();
	FridaDeviceManager *device_manager = frida_device_manager_new ();
	if (!device_manager) {
		printf ("Cannot open device manager\n");
		return 1;
	}
	FridaDevice *device = frida_device_manager_get_device_by_type_sync (device_manager, FRIDA_DEVICE_TYPE_LOCAL, 0, cancellable, &error);
	if (error || !device) {
		printf ("Cannot open local frida device\n");
		return 1;
	}
	char buf[1024];
	FridaCompiler *compiler = frida_compiler_new (device_manager);
	// g_signal_connect (compiler, "diagnostics", G_CALLBACK (on_compiler_diagnostics), rf);
	FridaBuildOptions * fbo = frida_build_options_new ();
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
		// compile_file (argv[i]);
		char *slash = strrchr (filename, '/');
		if (slash) {
			char *ofilename = filename;
			*slash = 0;
			char *root = strdup (filename);
			filename = strdup (slash + 1);
			frida_compiler_options_set_project_root (fco, root); // /Users/pancake/prg/r2frida/src/agent/");
			free (root);
			// free (ofilename);
		}
		g_signal_connect (compiler, "diagnostics", G_CALLBACK (on_compiler_diagnostics), NULL);
		char *slurpedData = frida_compiler_build_sync (compiler, filename, FRIDA_BUILD_OPTIONS (fco), NULL, &error);
		if (error || !slurpedData) {
			fprintf (stderr, "ERROR: %s\n", error->message);
		} else {
			printf ("%s\n", slurpedData);
		}
		free (slurpedData);
		free (filename);
	}
	g_object_unref (compiler);
	g_object_unref (device_manager);
	return 0;
}
