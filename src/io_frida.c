/* radare2 - MIT - Copyright 2016-2018 - pancake, oleavr, mrmacete */

#include <r_core.h>
#include <r_io.h>
#include <r_lib.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#ifndef WITH_CYLANG
#define WITH_CYLANG 1
#endif
#if WITH_CYLANG
#include "cylang.h"
#endif
#include "frida-core.h"

typedef struct {
	const char * cmd_string;
	ut64 serial;
	JsonObject * _cmd_json;
} RFPendingCmd;

typedef struct {
	FridaDevice *device;
	FridaSession *session;
	FridaScript *script;

	guint pid;
	GMutex lock;
	GCond cond;
	bool suspended;
	volatile bool detached;
	volatile FridaSessionDetachReason detach_reason;
	volatile bool received_reply;
	JsonObject *reply_stanza;
	GBytes *reply_bytes;
	RCore *r2core;
	RFPendingCmd * pending_cmd;
} RIOFrida;

#define RIOFRIDA_DEV(x) (((RIOFrida*)x->data)->device)
#define RIOFRIDA_SESSION(x) (((RIOFrida*)x->data)->session)

static bool parse_target(const char *pathname, char **device_id, char **process_specifier, bool * spawn);
static bool resolve_device(FridaDeviceManager *manager, const char *device_id, FridaDevice **device);
static bool resolve_process(FridaDevice *device, const char *process_specifier, guint *pid);
static JsonBuilder *build_request(const char *type);
static JsonObject *perform_request(RIOFrida *rf, JsonBuilder *builder, GBytes *data, GBytes **bytes);
static void on_message(FridaScript *script, const char *message, GBytes *data, gpointer user_data);
static RFPendingCmd * pending_cmd_create(JsonObject * cmd_json);
static void pending_cmd_free(RFPendingCmd * pending_cmd);
static void perform_request_unlocked(RIOFrida *rf, JsonBuilder *builder, GBytes *data, GBytes **bytes);
static void exec_pending_cmd_if_needed(RIOFrida * rf);
static char *__system(RIO *io, RIODesc *fd, const char *command);

extern RIOPlugin r_io_plugin_frida;
static FridaDeviceManager *device_manager = NULL;
static int device_manager_count = 0;

#define src__agent__js r_io_frida_agent_code

static const unsigned char r_io_frida_agent_code[] = {
#include "_agent.h"
	, 0x00
};

static RIOFrida *r_io_frida_new(RIO *io) {
	if (!io) {
		return NULL;
	}
	RIOFrida *rf = R_NEW0 (RIOFrida);
	if (!rf) {
		return NULL;
	}

	rf->detached = false;
	rf->detach_reason = FRIDA_SESSION_DETACH_REASON_APPLICATION_REQUESTED;
	rf->received_reply = false;
	rf->r2core = io->user;
	if (!rf->r2core) {
		eprintf ("ERROR: r2frida cannot find the RCore instance from IO->user.\n");
		free (rf);
		return NULL;
	}
	rf->suspended = false;

	return rf;
}

static void r_io_frida_free(RIOFrida *rf) {
	if (!rf) {
		return;
	}

	g_clear_object (&rf->script);
	g_clear_object (&rf->session);
	g_clear_object (&rf->device);

	if (device_manager) {
		device_manager_count--;
		if (device_manager_count == 0) {
			frida_device_manager_close_sync (device_manager);
			g_object_unref (device_manager);
			device_manager = NULL;
		}
	}

	R_FREE (rf);
}

static bool __check(RIO *io, const char *pathname, bool many) {
	return g_str_has_prefix (pathname, "frida://");
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	RIOFrida *rf;
	char *device_id = NULL, *process_specifier = NULL;
	guint pid;
	GError *error = NULL;
	bool spawn;

	frida_init ();

	rf = r_io_frida_new (io);
	if (!rf) {
		goto error;
	}

	if (!device_manager) {
		device_manager = frida_device_manager_new ();
	}
	device_manager_count++;

	if (!__check (io, pathname, false)) {
		goto error;
	}

	if (!parse_target (pathname, &device_id, &process_specifier, &spawn)) {
		goto error;
	}

	if (!resolve_device (device_manager, device_id, &rf->device)) {
		goto error;
	}

	if (!spawn && !resolve_process (rf->device, process_specifier, &pid)) {
		goto error;
	}

	if (spawn) {
		char **argv = r_str_argv (process_specifier, NULL);
		if (!argv) {
			eprintf ("Invalid process specifier\n");
			goto error;
		}
		if (!*argv) {
			eprintf ("Invalid arguments for spawning\n");
			r_str_argv_free (argv);
			goto error;
		}

		FridaSpawnOptions *options = frida_spawn_options_new ();
		const int argc = g_strv_length (argv);
		if (argc > 1) {
			frida_spawn_options_set_argv (options, argv, argc);
		}
		rf->pid = frida_device_spawn_sync (rf->device, argv[0], options, &error);
		g_object_unref (options);
		r_str_argv_free (argv);

		if (error) {
			eprintf ("Cannot spawn: %s\n", error->message);
			goto error;
		}

		rf->suspended = true;
	} else {
		rf->pid = pid;
		rf->suspended = false;
	}

	rf->session = frida_device_attach_sync (rf->device, rf->pid, &error);
	if (error) {
		eprintf ("Cannot attach: %s\n", error->message);
		goto error;
	}

	rf->script = frida_session_create_script_sync (rf->session, "r2io",
		(const char *)r_io_frida_agent_code, &error);
	if (error) {
		eprintf ("Cannot create script: %s\n", error->message);
		goto error;
	}

	g_signal_connect (rf->script, "message", G_CALLBACK (on_message), rf);

	frida_script_load_sync (rf->script, &error);
	if (error) {
		eprintf ("Cannot load script: %s\n", error->message);
		goto error;
	}

	g_free (device_id);
	g_free (process_specifier);

	const char *autocompletions[] = {
		"!!!\\eval",
		"!!!\\e",
		"!!!\\i",
		"!!!\\ii",
		"!!!\\il",
		"!!!\\is",
		"!!!\\isa $flag",
		"!!!\\iE",
		"!!!\\iEa $flag",
		"!!!\\ic",
		"!!!\\ip",
		"!!!\\fd $flag",
		"!!!\\dd",
		"!!!\\?",
		"!!!\\?V",
		"!!!\\/",
		"!!!\\/w",
		"!!!\\/wj",
		"!!!\\/x",
		"!!!\\/xj",
		"!!!\\/v1 $flag",
		"!!!\\/v2 $flag",
		"!!!\\/v4 $flag",
		"!!!\\/v8 $flag",
		"!!!\\dt $flag",
		"!!!\\dt- $flag",
		"!!!\\dtr",
		"!!!\\dtS",
		"!!!\\dc",
		"!!!\\di",
		"!!!\\dl",
		"!!!\\dl2",
		"!!!\\dx",
		"!!!\\dm",
		"!!!\\dma",
		"!!!\\dma-",
		"!!!\\dmas",
		"!!!\\dmad",
		"!!!\\dmal",
		"!!!\\dmm",
		"!!!\\dmh",
		"!!!\\dmhm",
		"!!!\\dmp $flag",
		"!!!\\db",
		"!!!\\dp",
		"!!!\\dpt",
		"!!!\\dr",
		"!!!\\drj",
		"!!!\\. $file",
		NULL
	};
	int i;
	for (i = 0; autocompletions[i]; i++) {
		r_core_cmd0 (rf->r2core, autocompletions[i]);
	}

	return r_io_desc_new (io, &r_io_plugin_frida, pathname, R_PERM_RWX, mode, rf);

error:
	g_clear_error (&error);

	g_free (device_id);
	g_free (process_specifier);

	r_io_frida_free (rf);

	return NULL;
}

static int __close(RIODesc *fd) {
	RIOFrida *rf;

	if (!fd || !fd->data) {
		return -1;
	}

	free (__system (fd->io, fd, "dc"));

	rf = fd->data;
	rf->detached = true;

	r_io_frida_free (fd->data);
	fd->data = NULL;

	return 0;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	RIOFrida *rf;
	JsonBuilder *builder;
	JsonObject *result;
	GBytes *bytes;
	gconstpointer data;
	gsize n;

	if (!fd || !fd->data) {
		return -1;
	}

	rf = fd->data;

	builder = build_request ("read");
	json_builder_set_member_name (builder, "offset");
	json_builder_add_int_value (builder, io->off);
	json_builder_set_member_name (builder, "count");
	json_builder_add_int_value (builder, count);

	result = perform_request (rf, builder, NULL, &bytes);
	if (!result) {
		return -1;
	}

	data = g_bytes_get_data (bytes, &n);
	memcpy (buf, data, R_MIN (n, count));

	json_object_unref (result);
	g_bytes_unref (bytes);

	return n;
}

static ut64 __lseek(RIO* io, RIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case SEEK_SET:
		io->off = offset;
		break;
	case SEEK_CUR:
		io->off += (int)offset;
		break;
	case SEEK_END:
		io->off = UT64_MAX;
		break;
	}
	return io->off;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	RIOFrida *rf;
	JsonBuilder *builder;
	int i;
	JsonObject *result;

	if (!fd || !fd->data) {
		return -1;
	}

	rf = fd->data;

	builder = build_request ("write");
	json_builder_set_member_name (builder, "offset");
	json_builder_add_int_value (builder, io->off);

	result = perform_request (rf, builder, g_bytes_new (buf, count), NULL);
	if (!result) {
		return -1;
	}
	json_object_unref (result);

	return count;
}

static bool __resize(RIO *io, RIODesc *fd, ut64 count) {
	return false;
}

static char *__system(RIO *io, RIODesc *fd, const char *command) {
	RIOFrida *rf;
	JsonBuilder *builder;
	JsonObject *result;
	const char *value;

	if (!fd || !fd->data) {
		return NULL;
	}

	if (!strcmp (command, "help") || !strcmp (command, "h") || !strcmp (command, "?")) {
		// TODO: move this into the .js
		io->cb_printf ("r2frida commands available via =! or \\ prefix\n"
		"?                          Show this help\n"
		"?V                         Show target Frida version\n"
		"/[x][j] <string|hexpairs>  Search hex/string pattern in memory ranges (see search.in=?)\n"
		"/w[j] string               Search wide string\n"
		"/v[1248][j] value          Search for a value honoring `e cfg.bigendian` of given width\n"
		"i                          Show target information\n"
		"ii[*]                      List imports\n"
		"il                         List libraries\n"
		"is[*] <lib>                List symbols of lib (local and global ones)\n"
		"isa[*] (<lib>) <sym>       Show address of symbol\n"
		"iE[*] <lib>                Same as is, but only for the export global ones\n"
		"ic <class>                 List Objective-C classes or methods of <class>\n"
		"ip <protocol>              List Objective-C protocols or methods of <protocol>\n"
		"fd[*j] <address>           Inverse symbol resolution\n"
		"db (<addr>|<sym>)          List or place breakpoint\n"
		"db- (<addr>|<sym>)|*       Remove breakpoint(s)\n"
		"dc                         Continue breakpoints or resume a spawned process\n"
		"dd[-][fd] ([newfd])        List, dup2 or close filedescriptors\n"
		"dm[.|j|*]                  Show memory regions\n"
		"dma <size>                 Allocate <size> bytes on the heap, address is returned\n"
		"dmas <string>              Allocate a string inited with <string> on the heap\n"
		"dmad <addr> <size>         Allocate <size> bytes on the heap, copy contents from <addr>\n"
		"dmal                       List live heap allocations created with dma[s]\n"
		"dma- (<addr>...)           Kill the allocations at <addr> (or all of them without param)\n"
		"dmp <addr> <size> <perms>  Change page at <address> with <size>, protection <perms> (rwx)\n"
		"dmm                        List all named squashed maps\n"
		"dmh                        List all heap allocated chunks\n"
		"dmhj                       List all heap allocated chunks in JSON\n"
		"dmh*                       Export heap chunks and regions as r2 flags\n"
		"dmhm                       Show which maps are used to allocate heap chunks\n"
		"dp                         Show current pid\n"
		"dpt                        Show threads\n"
		"dr                         Show thread registers (see dpt)\n"
		"env [k[=v]]                Get/set environment variable\n"
		"dl libname                 Dlopen a library\n"
		"dl2 libname [main]         Inject library using Frida's >= 8.2 new API\n"
		"dt <addr> ..               Trace list of addresses\n"
		"dt-                        Clear all tracing\n"
		"dtr <addr> (<regs>...)     Trace register values\n"
		"dtf <addr> [fmt]           Trace address with format (^ixzO) (see dtf?)\n"
		"dtSf[*j] [sym|addr]        Trace address or symbol using the stalker (Frida >= 10.3.13)\n"
		"dtS[*j] seconds            Trace all threads for given seconds using the stalker\n"
		"di[0,1,-1] [addr]          Intercept and replace return value of address\n"
		"dx [hexpairs]              Inject code and execute it (TODO)\n"
		"dxc [sym|addr] [args..]    Call the target symbol with given args\n"
		"e[?] [a[=b]]               List/get/set config evaluable vars\n"
		". script                   Run script\n"
		"<space> code..             Evaluate Cycript code\n"
		"eval code..                Evaluate Javascript code in agent side\n"
		"T[-*] [msg]                text-log console, useful to .\\T\n"
		);
		return NULL;
	}

	rf = fd->data;

	if (!strncmp (command, "dtf?", 4)) {
		io->cb_printf ("Usage: dtf [format] || dtf [addr] [fmt]\n");
		io->cb_printf ("  ^  = trace onEnter instead of onExit\n");
		io->cb_printf ("  +  = show backtrace on trace\n");
		io->cb_printf ("  x  = show hexadecimal argument\n");
		io->cb_printf ("  i  = show decimal argument\n");
		io->cb_printf ("  z  = show pointer to string\n");
		io->cb_printf ("  O  = show pointer to ObjC object\n");
	} else if (!strncmp (command, "e?", 2)) {
		io->cb_printf ("Usage: e [var[=value]]Evaluable vars\n");
		io->cb_printf ("  patch.code      = true\n");
		io->cb_printf ("  search.in       = perm:r--\n");
		io->cb_printf ("  search.quiet    = false\n");
		io->cb_printf ("  stalker.event   = compile\n");
		io->cb_printf ("  stalker.timeout = 300\n");
		io->cb_printf ("  stalker.in      = raw\n");
	} else if (!strncmp (command, "dl2", 3)) {
		if (command[3] == ' ') {
			GError *error = NULL;
			gchar *path = strdup (command + 4);
			gchar *entry = strchr (path, ' ');
			if (entry) {
				*entry++ = 0;
			} else {
				entry = "main";
			}
			frida_device_inject_library_file_sync (rf->device,
				rf->pid, path, entry, NULL, &error);
			free (path);
			if (error) {
				io->cb_printf ("frida_device_inject_library_file_sync: %s\n", error->message);
				g_clear_error (&error);
			} else {
				io->cb_printf ("done\n");
			}
		} else {
			io->cb_printf ("Usage: dl2 [shlib] [entrypoint-name]\n");
		}
		return NULL;
	} else if (!strcmp (command, "dc") && rf->suspended) {
		GError *error = NULL;
		frida_device_resume_sync (rf->device, rf->pid, &error);
		if (error) {
			io->cb_printf ("frida_device_resume_sync: %s\n", error->message);
			g_clear_error (&error);
		} else {
			rf->suspended = false;
			eprintf ("resumed spawned process.\n");
		}
		return NULL;
	}

	char *slurpedData = NULL;
	if (command[0] == '.') {
		switch (command[1]) {
		case ' ':
			slurpedData = r_file_slurp (command + 2, NULL);
			if (!slurpedData) {
				io->cb_printf ("Cannot slurp %s\n", command + 2);
				return NULL;
			}
			builder = build_request ("evaluate");
			json_builder_set_member_name (builder, "code");
			json_builder_add_string_value (builder, slurpedData);
			break;
		case '-':
			builder = build_request ("evaluate");
			json_builder_set_member_name (builder, "code");
			slurpedData = malloc (128);
			snprintf (slurpedData, 128, "r2frida.pluginUnregister('%s')", command + 2);
			json_builder_add_string_value (builder, slurpedData);
			break;
		case 0:
			/* list plugins */
			builder = build_request ("evaluate");
			json_builder_set_member_name (builder, "code");
			slurpedData = strdup ("console.log(r2frida.pluginList())");
			json_builder_add_string_value (builder, slurpedData);
			break;
		default:
			break;
		}
	}
	if (!slurpedData) {
		if (command[0] == ' ') {
			GError *error = NULL;
			char *js;
#if WITH_CYLANG
			js = cylang_compile (command + 1, &error);
			if (error) {
				io->cb_printf ("ERROR: %s\n", error->message);
				g_error_free (error);
				return NULL;
			}

			builder = build_request ("evaluate");
			json_builder_set_member_name (builder, "code");
			json_builder_add_string_value (builder, js);

			g_free (js);
#else
			// io->cb_printf ("error: r2frida compiled without cycript support. Use =!eval instead\n");
			// return -1;
			builder = build_request ("evaluate");
			json_builder_set_member_name (builder, "code");
			json_builder_add_string_value (builder, command + 1);
#endif
			// TODO: perhaps we could do some cheap syntax-highlighting of the result?
		} else {
			builder = build_request ("perform");
			json_builder_set_member_name (builder, "command");
			json_builder_add_string_value (builder, command);
		}
	}
	free (slurpedData);

	/* update state (seek and suspended) in agent */
	{
		char offstr[127] = {0};
		JsonBuilder *builder = build_request ("state");
		json_builder_set_member_name (builder, "offset");
		snprintf (offstr, sizeof (offstr), "0x%"PFMT64x, io->off);
		json_builder_add_string_value (builder, offstr);
		json_builder_set_member_name (builder, "suspended");
		json_builder_add_boolean_value (builder, rf->suspended);
		JsonObject *result = perform_request (rf, builder, NULL, NULL);
		if (!result) {
			return NULL;
		}
		json_object_unref (result);
	}

	result = perform_request (rf, builder, NULL, NULL);
	if (!result) {
		return NULL;
	}
	value = json_object_get_string_member (result, "value");
	char *sys_result = NULL;
	if (value && strcmp (value, "undefined")) {
		bool is_fs_io = command[0] == 'm';
		if (is_fs_io) {
			sys_result = r_str_newf ("%s", value);
		} else {
			io->cb_printf ("%s\n", value);
		}
	}
	json_object_unref (result);

	return sys_result;
}

static bool parse_target(const char *pathname, char **device_id, char **process_specifier, bool *spawn) {
	const char *first_field, *second_field;

	first_field = pathname + 8;
	*spawn = false;
	if (*first_field == '/' || !strncmp (first_field, "./", 2)) {
		// frida:///path/to/file
		*spawn = true;
		second_field = NULL;
	} else {
		// frida://device/...
		second_field = strchr (first_field, '/');
	}

	if (!second_field) {
		// frida://process or frida:///path/to/file
		*device_id = NULL;
		*process_specifier = g_strdup (first_field);
		return true;
	}
	second_field++;

	*device_id = g_strndup (first_field, second_field - first_field - 1);

	if (*second_field == '/') {
		// frida://device//com.your.app
		*spawn = true;
		second_field++;
	}

	// frida://device/process or frida://device//com.your.app
	*process_specifier = g_strdup (second_field);
	return true;
}

static bool resolve_device(FridaDeviceManager *manager, const char *device_id, FridaDevice **device) {
	GError *error = NULL;

	if (device_id != NULL) {
		if (strchr (device_id, ':')) {
			*device = frida_device_manager_add_remote_device_sync (manager, device_id, &error);
		} else {
			*device = frida_device_manager_get_device_by_id_sync (manager, device_id, 0, NULL, &error);
		}
	} else {
		*device = frida_device_manager_get_device_by_type_sync (manager, FRIDA_DEVICE_TYPE_LOCAL, 0, NULL, &error);
	}

	if (error != NULL) {
		eprintf ("%s\n", error->message);
		g_error_free (error);
		return false;
	}

	return true;
}

static bool resolve_process(FridaDevice *device, const char *process_specifier, guint *pid) {
	int number;
	FridaProcess *process;
	GError *error = NULL;

	number = atoi (process_specifier);
	if (number) {
		*pid = number;
		return true;
	}

	process = frida_device_get_process_by_name_sync (device, process_specifier, 0, NULL, &error);
	if (error != NULL) {
		eprintf ("%s\n", error->message);
		g_error_free (error);
		return false;
	}

	*pid = frida_process_get_pid (process);
	g_object_unref (process);

	return true;
}

static JsonBuilder *build_request(const char *type) {
	JsonBuilder *builder = json_builder_new ();
	json_builder_begin_object (builder);
	json_builder_set_member_name (builder, "type");
	json_builder_add_string_value (builder, type);
	json_builder_set_member_name (builder, "payload");
	json_builder_begin_object (builder);
	return builder;
}

static JsonObject *perform_request(RIOFrida *rf, JsonBuilder *builder, GBytes *data, GBytes **bytes) {
	JsonNode *root;
	char *message;
	GError *error = NULL;
	JsonObject *reply_stanza = NULL;
	GBytes *reply_bytes = NULL;

	json_builder_end_object (builder);
	json_builder_end_object (builder);
	root = json_builder_get_root (builder);
	message = json_to_string (root, FALSE);
	json_node_unref (root);
	g_object_unref (builder);

	frida_script_post_sync (rf->script, message, data, &error);

	g_free (message);
	g_bytes_unref (data);

	if (error) {
		eprintf ("error: %s\n", error->message);
		g_error_free (error);
		return NULL;
	}

	g_mutex_lock (&rf->lock);

	exec_pending_cmd_if_needed (rf);

	while (!rf->detached && !rf->received_reply) {
		g_cond_wait (&rf->cond, &rf->lock);
		exec_pending_cmd_if_needed (rf);
	}

	if (rf->received_reply) {
		reply_stanza = rf->reply_stanza;
		reply_bytes = rf->reply_bytes;
		rf->reply_stanza = NULL;
		rf->reply_bytes = NULL;
		rf->received_reply = false;
	}

	g_mutex_unlock (&rf->lock);

	if (!reply_stanza) {
		switch (rf->detach_reason) {
		case FRIDA_SESSION_DETACH_REASON_APPLICATION_REQUESTED:
			break;
		case FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED:
			eprintf ("Target process terminated\n");
			break;
		case FRIDA_SESSION_DETACH_REASON_SERVER_TERMINATED:
			eprintf ("Server terminated\n");
			break;
		case FRIDA_SESSION_DETACH_REASON_DEVICE_LOST:
			eprintf ("Device lost\n");
			break;
		case FRIDA_SESSION_DETACH_REASON_PROCESS_REPLACED:
			eprintf ("Process replaced\n");
			break;
		}
		return NULL;
	}

	if (json_object_has_member (reply_stanza, "error")) {
		eprintf ("%s\n", json_object_get_string_member (reply_stanza, "error"));
		json_object_unref (reply_stanza);
		g_bytes_unref (reply_bytes);
		return NULL;
	}

	if (bytes) {
		*bytes = reply_bytes;
	} else {
		g_bytes_unref (reply_bytes);
	}

	return reply_stanza;
}

static void exec_pending_cmd_if_needed(RIOFrida * rf) {
	if (!rf->pending_cmd) {
		return;
	}
	// TODO: use io->cb_core_cmdstr instead to avoid depending on RCore directly
	char * output = r_core_cmd_str (rf->r2core, rf->pending_cmd->cmd_string);

	ut64 serial = rf->pending_cmd->serial;
	pending_cmd_free (rf->pending_cmd);
	rf->pending_cmd = NULL;

	if (output) {
		JsonBuilder * builder = build_request ("cmd");
		json_builder_set_member_name (builder, "output");
		json_builder_add_string_value (builder, output);
		json_builder_set_member_name (builder, "serial");
		json_builder_add_int_value (builder, serial);

		R_FREE (output);

		perform_request_unlocked (rf, builder, NULL, NULL);
	}
}

static void perform_request_unlocked(RIOFrida *rf, JsonBuilder *builder, GBytes *data, GBytes **bytes) {
	GError *error = NULL;

	json_builder_end_object (builder);
	json_builder_end_object (builder);
	JsonNode *root = json_builder_get_root (builder);
	char *message = json_to_string (root, FALSE);
	json_node_unref (root);
	g_object_unref (builder);

	frida_script_post_sync (rf->script, message, data, &error);

	g_free (message);
	g_bytes_unref (data);

	if (error) {
		eprintf ("error: %s\n", error->message);
		g_error_free (error);
	}
}

static void on_stanza(RIOFrida *rf, JsonObject *stanza, GBytes *bytes) {
	g_mutex_lock (&rf->lock);

	g_assert (!rf->reply_stanza && !rf->reply_bytes);

	rf->received_reply = true;
	rf->reply_stanza = stanza;
	rf->reply_bytes = bytes? g_bytes_ref (bytes): NULL;
	g_cond_signal (&rf->cond);

	g_mutex_unlock (&rf->lock);
}

static void on_detached(FridaSession *session, FridaSessionDetachReason reason, gpointer user_data) {
	RIOFrida *rf = user_data;
	g_mutex_lock (&rf->lock);
	rf->detached = true;
	rf->detach_reason = reason;
	g_cond_signal (&rf->cond);
	g_mutex_unlock (&rf->lock);
}

static void on_cmd(RIOFrida *rf, JsonObject *cmd_stanza) {
	g_mutex_lock (&rf->lock);
	g_assert (!rf->pending_cmd);
	rf->pending_cmd = pending_cmd_create (cmd_stanza);
	g_cond_signal (&rf->cond);
	g_mutex_unlock (&rf->lock);
}

static void on_message(FridaScript *script, const char *message, GBytes *data, gpointer user_data) {
	RIOFrida *rf = user_data;
	JsonParser *parser;
	JsonObject *root;
	const char *type;

	parser = json_parser_new ();
	json_parser_load_from_data (parser, message, -1, NULL);

	root = json_node_get_object (json_parser_get_root (parser));
	type = json_object_get_string_member (root, "type");

	if (!strcmp (type, "send")) {
		JsonObject *payload = json_object_ref (json_object_get_object_member (root, "payload"));
		const char *name = json_object_get_string_member (payload, "name");
		if (!strcmp (name, "reply")) {
			on_stanza (rf,
				json_object_ref (json_object_get_object_member (payload, "stanza")),
				data);
		} else if (!strcmp (name, "cmd")) {
			on_cmd (rf,
				json_object_get_object_member (payload, "stanza"));
		}
		json_object_unref (payload);
	} else if (!strcmp (type, "log")) {
		eprintf ("%s\n", json_object_get_string_member (root, "payload"));
	} else {
		eprintf ("Unhandled message: %s\n", message);
	}

	g_object_unref (parser);
}

static RFPendingCmd * pending_cmd_create(JsonObject * cmd_json) {
	RFPendingCmd *pcmd = R_NEW0 (RFPendingCmd);
	if (pcmd) {
		pcmd->_cmd_json = json_object_ref (cmd_json);
		pcmd->cmd_string = json_object_get_string_member (cmd_json, "cmd");
		pcmd->serial = json_object_get_int_member (cmd_json, "serial");
	}
	return pcmd;
}

static void pending_cmd_free(RFPendingCmd * pending_cmd) {
	if (pending_cmd->_cmd_json) {
		json_object_unref (pending_cmd->_cmd_json);
	}
	R_FREE (pending_cmd);
}

RIOPlugin r_io_plugin_frida = {
	.name = "frida",
	.desc = "frida:// io plugin",
	.license = "MIT",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __check,
	.lseek = __lseek,
	.write = __write,
	.resize = __resize,
	.system = __system,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_frida,
	.version = R2_VERSION
};
#endif