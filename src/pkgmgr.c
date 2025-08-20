/* radare2 - MIT - Copyright 2025 - oleavr */

#include "frida-core.h"
#include <unistd.h>
#include <sys/resource.h>
#include <string.h>

static void print_package_info(FridaPackage *package, gboolean use_color);
static void maybe_raise_fd_limit(void);

int pkgmgr_search(const char *registry, const char *query, gboolean json_output, int offset, int limit) {
	GError *error = NULL;
	FridaPackageSearchOptions *search = NULL;
	FridaPackageSearchResult *result = NULL;
	FridaPackageList *packages = NULL;
	gint n;
	guint total;
	gboolean use_color = isatty (STDOUT_FILENO) && !json_output;
	int rc = 0;

	FridaPackageManager *pm = frida_package_manager_new ();
	if (registry != NULL) {
		frida_package_manager_set_registry (pm, registry);
	}

	search = frida_package_search_options_new ();
	if (offset != -1) {
		frida_package_search_options_set_offset (search, offset);
	}
	if (limit != -1) {
		frida_package_search_options_set_limit (search, limit);
	}

	result = frida_package_manager_search_sync (pm, query ? query : "", search, NULL, &error);
	if (error != NULL) {
		g_printerr ("Search failed: %s\n", error->message);
		g_error_free (error);
		rc = 1;
		goto beach;
	}

	packages = frida_package_search_result_get_packages (result);
	n = frida_package_list_size (packages);
	total = frida_package_search_result_get_total (result);

	if (json_output) {
		JsonBuilder *b;
		JsonNode *root;
		gchar *json;

		b = json_builder_new_immutable ();
		json_builder_begin_object (b);

		json_builder_set_member_name (b, "packages");
		json_builder_begin_array (b);

		for (guint i = 0; i != n; i++) {
			FridaPackage *pkg;
			const gchar *description;

			pkg = frida_package_list_get (packages, i);

			json_builder_begin_object (b);

			json_builder_set_member_name (b, "name");
			json_builder_add_string_value (b, frida_package_get_name (pkg));

			json_builder_set_member_name (b, "version");
			json_builder_add_string_value (b, frida_package_get_version (pkg));

			description = frida_package_get_description (pkg);
			if (description != NULL) {
				json_builder_set_member_name (b, "description");
				json_builder_add_string_value (b, description);
			}

			json_builder_set_member_name (b, "url");
			json_builder_add_string_value (b, frida_package_get_url (pkg));

			json_builder_end_object (b);

			g_object_unref (pkg);
		}

		json_builder_end_array (b);

		json_builder_set_member_name (b, "total");
		json_builder_add_int_value (b, total);

		json_builder_end_object (b);

		root = json_builder_get_root (b);
		json = json_to_string (root, TRUE);
		g_print ("%s\n", json);
		g_free (json);
		json_node_unref (root);
		g_object_unref (b);
	} else {
		for (guint i = 0; i != n; i++) {
			FridaPackage *pkg = frida_package_list_get (packages, i);
			print_package_info (pkg, use_color);
			g_object_unref (pkg);
		}

		int shown = n;
		int earlier = offset;
		int later = total - (offset + shown);

		if ((earlier > 0) || (later > 0)) {
			g_print ("… ");
			if (earlier > 0) {
				g_print ("%d earlier", earlier);
				if (later > 0) {
					g_print(" and ");
				}
			}
			if (later > 0) {
				g_print ("%d more", later);
			}
			g_print (". Use --limit and --offset to navigate through results.\n");
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
	FridaPackageManager *pm = NULL;
	FridaPackageInstallOptions *install = NULL;
	FridaPackageInstallResult *result = NULL;
	int rc = 0;

	maybe_raise_fd_limit ();

	pm = frida_package_manager_new ();
	if (registry != NULL) {
		frida_package_manager_set_registry (pm, registry);
	}

	install = frida_package_install_options_new ();
	if (project_root != NULL) {
		frida_package_install_options_set_project_root (install, project_root);
	}
	if (save_dev || save_optional) {
		frida_package_install_options_set_role (install,
			save_dev ? FRIDA_PACKAGE_ROLE_DEVELOPMENT : FRIDA_PACKAGE_ROLE_OPTIONAL);
	}
	for (int i = 0; i < nspecs; i++) {
		frida_package_install_options_add_spec (install, specs[i]);
	}
	if (omits != NULL) {
		for (gchar **cur = omits; *cur != NULL; cur++) {
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
		for (gint i = 0; i != 32; i++) {
			g_print (" ");
		}
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
