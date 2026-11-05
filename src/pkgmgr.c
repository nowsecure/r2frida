/* radare2 - MIT - Copyright 2025 - oleavr */

#include "frida-core.h"
#include <r_util.h>

#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif

// Frida 17.25 probes node_modules/<pkg>/package.json before installing each package
// but fails to catch the "file not found" error, so seed placeholders it can read.
// The probe sees no name/version, treats the package as missing and replaces the dir.
// Unpacking a package wipes the placeholders of its nested node_modules, so these are
// seeded again from the install-progress signal, before the nested packages are probed.
#define PLACEHOLDER "{\"r2frida-placeholder\":true}\n"

typedef struct {
	char *path; // lockfile key, e.g. node_modules/a/node_modules/b
	char *spec; // name@version
} LockEntry;

typedef struct {
	char *root;
	RList *entries;
	RList *placeholders;
} Placeholders;

static void print_package_info(FridaPackage *package, gboolean use_color);
static void maybe_raise_fd_limit(void);

static void lock_entry_free(LockEntry *e) {
	if (e) {
		free (e->path);
		free (e->spec);
		free (e);
	}
}

static void add_placeholder(Placeholders *ph, const char *path) {
	char *dir = r_file_new (ph->root, path, NULL);
	char *pkg_json = r_file_new (dir, "package.json", NULL);
	if (!r_file_exists (pkg_json) && r_sys_mkdirp (dir) && r_file_dump (pkg_json, (const ut8 *)PLACEHOLDER, -1, false)) {
		r_list_append (ph->placeholders, dir);
		dir = NULL;
	}
	free (pkg_json);
	free (dir);
}

static void placeholders_init(Placeholders *ph, const char *project_root) {
	ph->root = project_root? strdup (project_root): r_sys_getdir ();
	ph->entries = r_list_newf ((RListFree)lock_entry_free);
	ph->placeholders = r_list_newf (free);
	char *lock_path = r_file_new (ph->root, "package-lock.json", NULL);
	char *text = r_file_slurp (lock_path, NULL);
	RJson *lock = text? r_json_parse (text): NULL;
	const RJson *pkgs = lock? r_json_get (lock, "packages"): NULL;
	const RJson *p;
	for (p = (pkgs && pkgs->type == R_JSON_OBJECT)? pkgs->children.first: NULL; p; p = p->next) {
		const char *base = r_str_rstr (p->key, "node_modules/");
		const RJson *name = r_json_get (p, "name");
		const RJson *version = r_json_get (p, "version");
		if (!base || !version || version->type != R_JSON_STRING) {
			continue;
		}
		LockEntry *e = R_NEW0 (LockEntry);
		e->path = strdup (p->key);
		e->spec = r_str_newf ("%s@%s", (name && name->type == R_JSON_STRING)? name->str_value: base + strlen ("node_modules/"), version->str_value);
		r_list_append (ph->entries, e);
		add_placeholder (ph, e->path);
	}
	r_json_free (lock);
	free (text);
	free (lock_path);
}

static void on_install_progress(FridaPackageManager *pm, FridaPackageInstallPhase phase, gdouble fraction, const gchar *details, gpointer user_data) {
	Placeholders *ph = user_data;
	if (phase != FRIDA_PACKAGE_INSTALL_PHASE_PACKAGE_INSTALLED || !details) {
		return;
	}
	RListIter *iter, *iter2;
	LockEntry *e, *child;
	r_list_foreach (ph->entries, iter, e) {
		if (strcmp (e->spec, details)) {
			continue;
		}
		char *prefix = r_str_newf ("%s/node_modules/", e->path);
		r_list_foreach (ph->entries, iter2, child) {
			if (r_str_startswith (child->path, prefix)) {
				add_placeholder (ph, child->path);
			}
		}
		free (prefix);
	}
}

// Remove placeholders of packages that were not installed (i.e. omitted ones)
static void placeholders_fini(Placeholders *ph) {
	RListIter *iter;
	const char *dir;
	r_list_foreach (ph->placeholders, iter, dir) {
		char *pkg_json = r_file_new (dir, "package.json", NULL);
		char *data = r_file_slurp (pkg_json, NULL);
		if (data && !strcmp (data, PLACEHOLDER)) {
			r_file_rm (pkg_json);
			r_file_rm (dir);
		}
		free (data);
		free (pkg_json);
	}
	r_list_free (ph->placeholders);
	r_list_free (ph->entries);
	free (ph->root);
}

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

	FridaPackageSearchResult *result = frida_package_manager_search_sync (pm, query? query: "", search, NULL, &error);
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
			save_dev? FRIDA_PACKAGE_ROLE_DEVELOPMENT: FRIDA_PACKAGE_ROLE_OPTIONAL);
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

	Placeholders ph;
	placeholders_init (&ph, project_root);
	gulong sig = g_signal_connect (pm, "install-progress", G_CALLBACK (on_install_progress), &ph);
	result = frida_package_manager_install_sync (pm, install, NULL, &error);
	g_signal_handler_disconnect (pm, sig);
	placeholders_fini (&ph);
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
				n == 1? "": "s",
				(projroot != NULL)? projroot: current_dir);
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
			name,
			version);
	} else {
		g_print ("%s@%s", name, version);
	}

	gint name_len = strlen (name) + 1 + strlen (version);
	gint gap = MAX (1, 32 - name_len);

	for (gint i = 0; i != gap; i++) {
		g_print (" ");
	}

	g_print ("%s\n", (description != NULL)? description: "");
	if (R_STR_ISNOTEMPTY (url)) {
		g_print ("  ");
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
