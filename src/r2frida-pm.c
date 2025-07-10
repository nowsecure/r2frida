/* radare2 - MIT - Copyright 2025 - oleavr */

#include "frida-core.h"

typedef enum {
	COMMAND_SEARCH,
	COMMAND_INSTALL
} Command;

typedef struct {
	Command command;
	gchar *registry;

	gchar *query;
	FridaPackageSearchOptions *search;
	gboolean json_output;

	FridaPackageInstallOptions *install;
	gboolean quiet;
} Options;

static gboolean parse_arguments(int argc, char **argv, Options *opts);
static void free_options(Options *opts);
static gint cmd_search(FridaPackageManager *pm, Options *opts);
static gint cmd_install(FridaPackageManager *pm, Options *opts);
static void print_package_info(FridaPackage *package, gboolean use_color);
static void maybe_raise_fd_limit(void);

int main(int argc, char **argv) {
	Options opts = {0};
	FridaPackageManager *pm = NULL;
	gint exit_code = 0;

	frida_init ();

	if (!parse_arguments (argc, argv, &opts)) {
		exit_code = 1;
		goto beach;
	}

	pm = frida_package_manager_new ();

	if (opts.registry != NULL) {
		frida_package_manager_set_registry (pm, opts.registry);
	}

	switch (opts.command) {
	case COMMAND_SEARCH:
		exit_code = cmd_search (pm, &opts);
		break;
	case COMMAND_INSTALL:
		exit_code = cmd_install (pm, &opts);
		break;
	default:
		g_printerr("Invalid command\n");
		exit_code = 1;
		break;
	}

beach:
	g_clear_object (&pm);
	free_options (&opts);

	return exit_code;
}

static gboolean parse_arguments(int argc, char **argv, Options *opts) {
	gboolean success = FALSE;

	gboolean help = FALSE;
	gchar *registry = NULL;

	gint offset = -1;
	gint limit = -1;
	gboolean json_output = FALSE;

	gchar *project_root = NULL;
	gboolean save_prod = FALSE;
	gboolean save_dev = FALSE;
	gboolean save_optional = FALSE;
	gchar **omits = NULL;
	gboolean quiet = FALSE;

	GOptionContext *context;
	GError *error = NULL;

	GOptionEntry global_entries[] = {
		{ "help", 'h', 0, G_OPTION_ARG_NONE, &help, "Show help message", NULL },
		{ "registry", 0, 0, G_OPTION_ARG_STRING, &registry, "Package registry to use", "HOST" },
		{ NULL, }
	};

	GOptionEntry search_entries[] = {
		{ "offset", 0, 0, G_OPTION_ARG_INT, &offset, "Result offset", "N" },
		{ "limit", 0, 0, G_OPTION_ARG_INT, &limit, "Max results", "N" },
		{ "json", 0, 0, G_OPTION_ARG_NONE, &json_output, "Emit raw JSON", NULL },
		{ NULL, }
	};

	GOptionEntry install_entries[] = {
		{ "project-root", 0, 0, G_OPTION_ARG_STRING, &project_root, "Project root directory", "DIR" },
		{ "save-prod", 'P', 0, G_OPTION_ARG_NONE, &save_prod, "Save as production dependencies", NULL },
		{ "save-dev", 'D', 0, G_OPTION_ARG_NONE, &save_dev, "Save as development dependencies", NULL },
		{ "save-optional", 'O', 0, G_OPTION_ARG_NONE, &save_optional, "Save as optional dependencies", NULL },
		{ "omit", 0, 0, G_OPTION_ARG_STRING_ARRAY, &omits, "Dependency types to skip", "TYPE" },
		{ "quiet", 0, 0, G_OPTION_ARG_NONE, &quiet, "Suppress progress bar", NULL },
		{ NULL, }
	};

	context = g_option_context_new ("<command> [...]");
	g_option_context_add_main_entries (context, global_entries, NULL);
	g_option_context_set_description (context,
		"Commands:\n"
		"  search [QUERY]          Search for packages\n"
		"  install [SPEC...]       Install one or more packages");
	g_option_context_set_ignore_unknown_options (context, TRUE);

	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		goto invalid_argument;
	}

	opts->registry = g_steal_pointer (&registry);

	if (help || argc < 2) {
		goto print_usage;
	}

	g_option_context_free (context);

	context = g_option_context_new (NULL);
	g_option_context_set_help_enabled (context, FALSE);

	if (strcmp (argv[1], "search") == 0) {
		g_option_context_set_summary (context, "Search for packages");
		g_option_context_add_main_entries (context, search_entries, NULL);

		opts->command = COMMAND_SEARCH;
	} else if (strcmp (argv[1], "install") == 0) {
		g_option_context_set_summary (context, "Install one or more packages");
		g_option_context_add_main_entries (context, install_entries, NULL);

		opts->command = COMMAND_INSTALL;
	} else {
		goto unknown_command;
	}

	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		goto invalid_argument;
	}

	switch (opts->command) {
	case COMMAND_SEARCH:
		opts->query = g_strdup ((argc > 2) ? argv[2] : "");

		opts->search = frida_package_search_options_new ();
		if (offset != -1) {
			frida_package_search_options_set_offset (opts->search, offset);
		}
		if (limit != -1) {
			frida_package_search_options_set_limit (opts->search, limit);
		}

		opts->json_output = json_output;

		break;
	case COMMAND_INSTALL:
		opts->install = frida_package_install_options_new ();
		if (project_root != NULL) {
			frida_package_install_options_set_project_root (opts->install, project_root);
		}
		if (save_dev || save_optional) {
			frida_package_install_options_set_role (opts->install,
				save_dev ? FRIDA_PACKAGE_ROLE_DEVELOPMENT : FRIDA_PACKAGE_ROLE_OPTIONAL);
		}
		for (int i = 2; i != argc; i++) {
			frida_package_install_options_add_spec (opts->install, argv[i]);
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
					goto invalid_omit_value;
				}
				frida_package_install_options_add_omit (opts->install, role);
			}
		}

		opts->quiet = quiet;

		break;
	default:
		g_assert_not_reached ();
	}

	success = TRUE;
	goto beach;

invalid_argument:
	{
		g_printerr ("%s\n", error->message);
		goto beach;
	}
print_usage:
	{
		gchar *help_text = g_option_context_get_help (context, TRUE, NULL);
		g_print ("%s", help_text);
		g_free (help_text);
		goto beach;
	}
unknown_command:
	{
		g_printerr ("Unknown command: %s\n", argv[1]);
		goto beach;
	}
invalid_omit_value:
	{
		g_printerr ("Invalid --omit argument, must be one of: dev, optional, peer\n");
		goto beach;
	}
beach:
	{
		g_clear_error (&error);
		g_option_context_free (context);

		g_strfreev (omits);
		g_free (project_root);

		g_free (registry);

		return success;
	}
}

static void free_options (Options *opts) {
	g_clear_object (&opts->install);

	g_clear_object (&opts->search);
	g_free (opts->query);

	g_free (opts->registry);
}

static gint cmd_search(FridaPackageManager *pm, Options *opts) {
	GError *error = NULL;
	FridaPackageSearchResult *result;
	FridaPackageList *packages;
	gint n;
	guint total;
	gboolean use_color = isatty (STDOUT_FILENO) && !opts->json_output;

	result = frida_package_manager_search_sync (pm, opts->query, opts->search, NULL, &error);
	if (error != NULL) {
		g_printerr ("Search failed: %s\n", error->message);
		g_error_free (error);
		return 1;
	}

	packages = frida_package_search_result_get_packages (result);
	n = frida_package_list_size (packages);

	total = frida_package_search_result_get_total (result);

	if (opts->json_output) {
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

		gint offset = frida_package_search_options_get_offset (opts->search);
		gint shown = n;
		gint earlier = offset;
		gint later = total - (offset + shown);

		if (earlier > 0 || later > 0) {
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

	g_object_unref (result);
	return 0;
}

static gint cmd_install(FridaPackageManager *pm, Options *opts) {
	GError *error = NULL;
	FridaPackageInstallResult *result;

	maybe_raise_fd_limit ();

	result = frida_package_manager_install_sync (pm, opts->install, NULL, &error);

	if (error != NULL) {
		g_printerr ("Install failed: %s\n", error->message);
		g_error_free (error);
		return 1;
	}

	if (!opts->quiet) {
		FridaPackageList *packages;
		gint n, i;

		packages = frida_package_install_result_get_packages (result);
		n = frida_package_list_size (packages);

		if (n != 0) {
			const gchar *project_root;
			gchar *current_dir;

			for (i = 0; i != n; i++) {
				FridaPackage *pkg = frida_package_list_get (packages, i);
				const gchar *name = frida_package_get_name (pkg);
				const gchar *version = frida_package_get_version (pkg);
				g_print ("✓ %s@%s\n", name, version);
			}

			project_root = frida_package_install_options_get_project_root (opts->install);
			current_dir = g_get_current_dir ();

			g_print("\n%u package%s installed into %s\n",
				n,
				n == 1 ? "" : "s",
				(project_root != NULL) ? project_root : current_dir);

			g_free (current_dir);
		} else {
			g_print ("✔ up to date\n");
		}
	}

	g_object_unref (result);
	return 0;
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
