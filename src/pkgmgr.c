/* radare2 - MIT - Copyright 2025 - oleavr */

#include "frida-core.h"
#include <r_util.h>

#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif

static void print_package_info(FridaPackage *package, gboolean use_color);
static void maybe_raise_fd_limit(void);

int pkgmgr_search(const char *registry, const char *query, gboolean json_output, int offset, int limit) {
	GError *error = NULL;
	FridaPackageList *packages = NULL;
	guint total;
	gboolean use_color = isatty (STDOUT_FILENO) && !json_output;
	int rc = 0;

	FridaPackageManager *pm = frida_package_manager_new ();
	if (registry != NULL) {
		frida_package_manager_set_registry (pm, registry);
	}

	FridaPackageSearchOptions *search = frida_package_search_options_new ();
	if (offset != -1) {
		frida_package_search_options_set_offset (search, offset);
	}
	if (limit != -1) {
		frida_package_search_options_set_limit (search, limit);
	}

	FridaPackageSearchResult *result = frida_package_manager_search_sync (pm, query ? query : "", search, NULL, &error);
	if (error != NULL) {
		g_printerr ("Search failed: %s\n", error->message);
		g_error_free (error);
		rc = 1;
		goto beach;
	}

	packages = frida_package_search_result_get_packages (result);
	gint n = frida_package_list_size (packages);
	total = frida_package_search_result_get_total (result);

	if (json_output) {
		PJ *j = pj_new ();
		pj_o (j);
		pj_ko (j, "packages");
		pj_a (j);

		for (guint i = 0; i != n; i++) {

			FridaPackage *pkg = frida_package_list_get (packages, i);
			pj_o (j);
			pj_ks (j, "name", frida_package_get_name (pkg));
			pj_ks (j, "version", frida_package_get_version (pkg));
			const gchar *description = frida_package_get_description (pkg);
			if (description != NULL) {
				pj_ks (j, "description", description);
			}
			pj_ks (j, "url", frida_package_get_url (pkg));
			pj_end (j);
			g_object_unref (pkg);
		}
		pj_end (j);
		pj_kN (j, "total", total);
		pj_end (j);

		char *out = pj_drain (j);
		if (out) {
			g_print ("%s\n", out);
			free (out);
		}
	} else {
		guint i;
		for (i = 0; i != n; i++) {
			FridaPackage *pkg = frida_package_list_get (packages, i);
			print_package_info (pkg, use_color);
			g_object_unref (pkg);
		}
	}

beach:
	g_clear_object (&result);
	g_clear_object (&pm);
	g_clear_object (&search);
	return rc;
}

int pkgmgr_install(const char *registry, char **specs, int nspecs, const char *project_root, gboolean save_dev, gboolean save_prod, gboolean save_optional, char **omits, gboolean quiet) {
	GError *error = NULL;
	FridaPackageInstallResult *result = NULL;
	int i, rc = 0;

	maybe_raise_fd_limit ();

	FridaPackageManager *pm = frida_package_manager_new ();
	if (registry != NULL) {
		frida_package_manager_set_registry (pm, registry);
	}

	FridaPackageInstallOptions *install = frida_package_install_options_new ();
	if (project_root != NULL) {
		frida_package_install_options_set_project_root (install, project_root);
	}
	if (save_dev || save_optional) {
		frida_package_install_options_set_role (install,
			save_dev ? FRIDA_PACKAGE_ROLE_DEVELOPMENT : FRIDA_PACKAGE_ROLE_OPTIONAL);
	}
	for (i = 0; i < nspecs; i++) {
		frida_package_install_options_add_spec (install, specs[i]);
	}
	if (omits != NULL) {
		gchar **cur;
		for (cur = omits; *cur != NULL; cur++) {
			FridaPackageRole role;
			const gchar *s = *cur;
			if (strcmp (s, "dev") == 0) {
				role = FRIDA_PACKAGE_ROLE_DEVELOPMENT;
			} else if (strcmp (s, "optional") == 0) {
				role = FRIDA_PACKAGE_ROLE_OPTIONAL;
			} else if (strcmp (s, "peer") == 0) {
				role = FRIDA_PACKAGE_ROLE_PEER;
			} else {
				g_printerr ("Invalid --omit argument, must be one of: dev, optional, peer\n");
				role = FRIDA_PACKAGE_ROLE_PEER; // fallback
			}
			frida_package_install_options_add_omit (install, role);
		}
	}

	result = frida_package_manager_install_sync (pm, install, NULL, &error);
	if (error != NULL) {
		g_printerr ("Install failed: %s\n", error->message);
		g_error_free (error);
		rc = 1;
		goto beach;
	}

	if (!quiet) {
		FridaPackageList *packages;
		gint n, i;

		packages = frida_package_install_result_get_packages (result);
		n = frida_package_list_size (packages);

		if (n != 0) {
			const gchar *projroot;
			char *current_dir;

			for (i = 0; i != n; i++) {
				FridaPackage *pkg = frida_package_list_get (packages, i);
				const gchar *name = frida_package_get_name (pkg);
				const gchar *version = frida_package_get_version (pkg);
				g_print ("✓ %s@%s\n", name, version);
			}

			projroot = frida_package_install_options_get_project_root (install);
			current_dir = g_get_current_dir ();

			g_print ("\n%u package%s installed into %s\n",
				n,
				n == 1 ? "" : "s",
				(projroot != NULL) ? projroot : current_dir);
			g_free (current_dir);
		} else {
			g_print ("✔ up to date\n");
		}
	}

beach:
	g_clear_object (&result);
	g_clear_object (&pm);
	g_clear_object (&install);
	return rc;
}

static void print_package_info(FridaPackage *package, gboolean use_color) {
	const gchar *name = frida_package_get_name (package);
	const gchar *version = frida_package_get_version (package);
	const gchar *description = frida_package_get_description (package);
	const gchar *url = frida_package_get_url (package);

	if (use_color) {
		g_print ("\033[38;2;156;156;156m%s\033[0m\033[38;2;158;158;158m@%s\033[0m",
			name, version);
	} else {
		g_print ("%s@%s", name, version);
	}

	gint name_len = strlen (name) + 1 + strlen (version);
	gint gap = MAX (1, 32 - name_len);

	for (gint i = 0; i != gap; i++) {
		g_print (" ");
	}

	g_print ("%s\n", (description != NULL) ? description : "");
	if (url && strlen (url) > 0) {
		g_print ("%s", r_str_pad (' ', 32));
		if (use_color) {
			g_print ("\033[38;2;156;156;156m%s\033[0m\n", url);
		} else {
			g_print ("%s\n", url);
		}
	}

	g_print ("\n");
}

static void maybe_raise_fd_limit(void) {
#ifdef __APPLE__
	struct rlimit rl;

	getrlimit (RLIMIT_NOFILE, &rl);
	rl.rlim_cur = rl.rlim_max;
	setrlimit (RLIMIT_NOFILE, &rl);
#endif
}
