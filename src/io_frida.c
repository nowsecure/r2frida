/* radare2 - MIT - Copyright 2016-2019 - pancake, oleavr, mrmacete */

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
	char *device_id;
	char *process_specifier;
	guint pid;
	bool pid_valid;
	bool spawn;
} R2FridaLaunchOptions;

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
	volatile FridaCrash *crash;
	volatile bool received_reply;
	JsonObject *reply_stanza;
	GBytes *reply_bytes;
	RCore *r2core;
	RFPendingCmd * pending_cmd;
	char *crash_report;
} RIOFrida;

#define RIOFRIDA_DEV(x) (((RIOFrida*)x->data)->device)
#define RIOFRIDA_SESSION(x) (((RIOFrida*)x->data)->session)

static bool parse_target(const char *pathname, R2FridaLaunchOptions *lo);
static bool resolve_device(FridaDeviceManager *manager, const char *device_id, FridaDevice **device);
static bool resolve_process(FridaDevice *device, R2FridaLaunchOptions *lo);
static JsonBuilder *build_request(const char *type);
static JsonObject *perform_request(RIOFrida *rf, JsonBuilder *builder, GBytes *data, GBytes **bytes);
static RFPendingCmd * pending_cmd_create(JsonObject * cmd_json);
static void pending_cmd_free(RFPendingCmd * pending_cmd);
static void perform_request_unlocked(RIOFrida *rf, JsonBuilder *builder, GBytes *data, GBytes **bytes);
static void exec_pending_cmd_if_needed(RIOFrida * rf);
static char *__system(RIO *io, RIODesc *fd, const char *command);
static int atopid(const char *maybe_pid, bool *valid);

// event handlers
static void on_message(FridaScript *script, const char *message, GBytes *data, gpointer user_data);
static void on_detached(FridaSession *session, FridaSessionDetachReason reason, FridaCrash *crash, gpointer user_data);

static void dumpDevices(void);
static void dumpProcesses(FridaDevice *device);
static void dumpApplications(FridaDevice *device);
static gint compareDevices(gconstpointer element_a, gconstpointer element_b);
static gint compareProcesses(gconstpointer element_a, gconstpointer element_b);
static gint computeDeviceScore(FridaDevice *device);
static gint computeProcessScore(FridaProcess *process);

extern RIOPlugin r_io_plugin_frida;
static FridaDeviceManager *device_manager = NULL;
static int device_manager_count = 0;

#define src__agent__js r_io_frida_agent_code

static const gchar r_io_frida_agent_code[] = {
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
	rf->detach_reason = 0;
	rf->crash = NULL;
	rf->crash_report = NULL;
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

static R2FridaLaunchOptions *r2frida_launchopt_new (const char *pathname) {
	R2FridaLaunchOptions *lo = R_NEW0(R2FridaLaunchOptions);
	if (lo) {
		// lo
	}
	return lo;
}

static void r2frida_launchopt_free(R2FridaLaunchOptions *lo) {
	g_free (lo->device_id);
	g_free (lo->process_specifier);
}

static void r_io_frida_free(RIOFrida *rf) {
	if (!rf) {
		return;
	}

	free (rf->crash_report);
	g_clear_object (&rf->crash);
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

static const char *detachReasonAsString(RIOFrida *rf) {
	if (!rf->detach_reason) {
		return "NONE";
	}
	GEnumClass *enum_class = g_type_class_ref (FRIDA_TYPE_SESSION_DETACH_REASON);
	GEnumValue *enum_value = g_enum_get_value (enum_class, rf->detach_reason);
	g_type_class_unref (enum_class);
	return enum_value->value_name;
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

static bool __check(RIO *io, const char *pathname, bool many) {
	return g_str_has_prefix (pathname, "frida://");
}

static bool user_wants_v8() {
	bool do_want = true;
	char *env = r_sys_getenv ("R2FRIDA_DISABLE_V8");
	if (env) {
		if (*env) {
			do_want = false;
		}
		free (env);
	}
	return do_want;
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	RIOFrida *rf;
	GError *error = NULL;

	R2FridaLaunchOptions *lo = r2frida_launchopt_new (pathname);
	if (!lo) {
		return NULL;
	}

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

	if (!parse_target (pathname, lo)) {
		goto error;
	}
	if (!resolve_device (device_manager, lo->device_id, &rf->device)) {
		goto error;
	}
	if (!rf->device) {
		goto error;
	}

	if (!lo->spawn && !resolve_process (rf->device, lo)) {
		goto error;
	}

	if (lo->spawn) {
		char **argv = r_str_argv (lo->process_specifier, NULL);
		if (!argv) {
			eprintf ("Invalid process specifier\n");
			goto error;
		}
		if (!*argv) {
			eprintf ("Invalid arguments for spawning\n");
			dumpApplications (rf->device);
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
		rf->pid = lo->pid;
		rf->suspended = false;
	}

	rf->session = frida_device_attach_sync (rf->device, rf->pid, &error);
	if (error) {
		eprintf ("Cannot attach: %s\n", error->message);
		goto error;
	}

	FridaScriptOptions * options = frida_script_options_new ();
	frida_script_options_set_name (options, "r2io");
	if (user_wants_v8 ()) {
		frida_script_options_set_runtime (options, FRIDA_SCRIPT_RUNTIME_V8);
	}

	char *r2f_as = r_sys_getenv ("R2FRIDA_AGENT_SCRIPT");
	if (r2f_as && r2f_as) {
		char *agent_code = r_file_slurp (r2f_as, NULL);
		if (agent_code) {
			rf->script = frida_session_create_script_sync (rf->session, agent_code, options, &error);
			if (error) {
				eprintf ("Cannot create script: %s\n", error->message);
				goto error;
			}
			free (agent_code);
		} else {
			eprintf ("Cannot slurp R2FRIDA_AGENT_SCRIPT\n");
		}
	} else {
		rf->script = frida_session_create_script_sync (rf->session, r_io_frida_agent_code, options, &error);
		if (error) {
			eprintf ("Cannot create script: %s\n", error->message);
			goto error;
		}
	}
	free (r2f_as);

	g_signal_connect (rf->script, "message", G_CALLBACK (on_message), rf);
	g_signal_connect (rf->session, "detached", G_CALLBACK (on_detached), rf);

	frida_script_load_sync (rf->script, &error);
	if (error) {
		eprintf ("Cannot load script: %s\n", error->message);
		goto error;
	}

	r2frida_launchopt_free (lo);

	const char *autocompletions[] = {
		"!!!\\eval",
		"!!!\\e",
		"!!!\\env",
		"!!!\\j",
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
		"!!!\\dth",
		"!!!\\dtr",
		"!!!\\dtS",
		"!!!\\dtSf $flag",
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
		"!!!\\dk",
		"!!!\\dkr",
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

	r2frida_launchopt_free (lo);

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
	GBytes *bytes;
	gsize n;

	r_return_val_if_fail (io && fd && fd->data && buf && count > 0, -1);

	RIOFrida *rf = fd->data;

	JsonBuilder *builder = build_request ("read");
	json_builder_set_member_name (builder, "offset");
	json_builder_add_int_value (builder, io->off);
	json_builder_set_member_name (builder, "count");
	json_builder_add_int_value (builder, count);

	JsonObject *result = perform_request (rf, builder, NULL, &bytes);
	if (!result) {
		return -1;
	}

	gconstpointer data = g_bytes_get_data (bytes, &n);
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
		". script                   Run script\n"
		"  frida-expression         Run given expresssion inside the agent\n"
		"j java-expression          Run given expresssion inside a Java.perform(function(){}) block\n"
		"/[x][j] <string|hexpairs>  Search hex/string pattern in memory ranges (see search.in=?)\n"
		"/v[1248][j] value          Search for a value honoring `e cfg.bigendian` of given width\n"
		"/w[j] string               Search wide string\n"
		"<space> code..             Evaluate Cycript code\n"
		"?                          Show this help\n"
		"?V                         Show target Frida version\n"
		"d.                         Start the chrome tools debugger\n"
		"db (<addr>|<sym>)          List or place breakpoint\n"
		"db- (<addr>|<sym>)|*       Remove breakpoint(s)\n"
		"dc                         Continue breakpoints or resume a spawned process\n"
		"dd[j-][fd] ([newfd])       List, dup2 or close filedescriptors (ddj for JSON)\n"
		"di[0,1,-1] [addr]          Intercept and replace return value of address\n"
		"dk ([pid]) [sig]           Send signal to pid (kill -<sig> <pid>)\n"
		"dk [signal] [pid]          Send specific signal to specific pid in the remote system\n"
		"dkr                        Print the crash report (if the app has crashed)\n"
		"dkr                        Print the crash report (if the app has crashed)\n"
		"dl libname                 Dlopen a library (Android see chcon)\n"
		"dl2 libname [main]         Inject library using Frida's >= 8.2 new API\n"
		"dm[.|j|*]                  Show memory regions\n"
		"dma <size>                 Allocate <size> bytes on the heap, address is returned\n"
		"dma- (<addr>...)           Kill the allocations at <addr> (or all of them without param)\n"
		"dmad <addr> <size>         Allocate <size> bytes on the heap, copy contents from <addr>\n"
		"dmal                       List live heap allocations created with dma[s]\n"
		"dmas <string>              Allocate a string inited with <string> on the heap\n"
		"dmh                        List all heap allocated chunks\n"
		"dmh*                       Export heap chunks and regions as r2 flags\n"
		"dmhj                       List all heap allocated chunks in JSON\n"
		"dmhm                       Show which maps are used to allocate heap chunks\n"
		"dmm                        List all named squashed maps\n"
		"dmp <addr> <size> <perms>  Change page at <address> with <size>, protection <perms> (rwx)\n"
		"dp                         Show current pid\n"
		"dpt                        Show threads\n"
		"dr                         Show thread registers (see dpt)\n"
		"dt (<addr>|<sym>) ..       Trace list of addresses or symbols\n"
		"dt-                        Clear all tracing\n"
		"dt.                        Trace at current offset\n"
		"dtf <addr> [fmt]           Trace address with format (^ixzO) (see dtf?)\n"
		"dth (addr|sym)(x:0 y:1 ..) Define function header (z=str,i=int,v=hex barray,s=barray)\n"
		"dtl[-*] [msg]              debug trace log console, useful to .\\T*\n"
		"dtr <addr> (<regs>...)     Trace register values\n"
		"dts[*j] seconds            Trace all threads for given seconds using the stalker\n"
		"dtsf[*j] [sym|addr]        Trace address or symbol using the stalker (Frida >= 10.3.13)\n"
		"dxc [sym|addr] [args..]    Call the target symbol with given args\n"
		"e[?] [a[=b]]               List/get/set config evaluable vars\n"
		"env [k[=v]]                Get/set environment variable\n"
		"eval code..                Evaluate Javascript code in agent side\n"
		"fd[*j] <address>           Inverse symbol resolution\n"
		"chcon file                 Change SELinux context (dl might require this)\n"
		"i                          Show target information\n"
		"iE[*] <lib>                Same as is, but only for the export global ones\n"
		"ic <class>                 List Objective-C classes or methods of <class>\n"
		"ii[*]                      List imports\n"
		"il                         List libraries\n"
		"ip <protocol>              List Objective-C protocols or methods of <protocol>\n"
		"is[*] <lib>                List symbols of lib (local and global ones)\n"
		"isa[*] (<lib>) <sym>       Show address of symbol\n"
		);
		return NULL;
	}

	rf = fd->data;
	if (!strncmp (command, "o/", 2)) {
		r_core_cmd0 (rf->r2core, "?E Yay!");
		return NULL;
	} else if (!strncmp (command, "d.", 2)) {
		int port = 0; // 9229
		if (command[2] == ' ') {
			port = r_num_math (NULL, command + 3);
		}
		GError *error = NULL;
		frida_session_enable_debugger_sync (rf->session, port, &error);
		if (error) {
			eprintf ("frida_session_enable_debugger_sync error: %s\n", error->message);
			g_error_free (error);
		}
		return NULL;
	} else if (!strncmp (command, "dtf?", 4)) {
		io->cb_printf ("Usage: dtf [format] || dtf [addr] [fmt]\n");
		io->cb_printf ("  ^  = trace onEnter instead of onExit\n");
		io->cb_printf ("  +  = show backtrace on trace\n");
		io->cb_printf (" p/x = show pointer in hexadecimal\n");
		io->cb_printf ("  c  = show value as a string (char)\n");
		io->cb_printf ("  i  = show decimal argument\n");
		io->cb_printf ("  z  = show pointer to string\n");
		io->cb_printf ("  s  = show string in place\n");
		io->cb_printf ("  O  = show pointer to ObjC object\n");
		io->cb_printf ("Undocumented: Z, S\n");
	} else if (!strncmp (command, "e?", 2)) {
		io->cb_printf ("Usage: e [var[=value]]Evaluable vars\n");
		io->cb_printf ("  patch.code      = true\n");
		io->cb_printf ("  search.in       = perm:r--\n");
		io->cb_printf ("  search.quiet    = false\n");
		io->cb_printf ("  stalker.event   = compile\n");
		io->cb_printf ("  stalker.timeout = 300\n");
		io->cb_printf ("  stalker.in      = raw\n");
	} else if (!strcmp (command, "s")) {
		io->cb_printf ("0x%08"PFMT64x, rf->r2core->offset);
		return NULL;
	} else if (!strncmp (command, "s ", 2)) {
		r_core_cmd0 (rf->r2core, command);
		return NULL;
	} else if (!strncmp (command, "dkr", 3)) {
		io->cb_printf ("DetachReason: %s\n", detachReasonAsString (rf));
		if (rf->crash_report) {
			io->cb_printf ("%s\n", rf->crash_report);
		}
		return NULL;
	} else if (!strncmp (command, "dl2", 3)) {
		if (command[3] == ' ') {
			GError *error = NULL;
			gchar *path = strdup (r_str_trim_ro (command + 3));
			if (path) {
				gchar *entry = strchr (path, ' ');
				if (entry) {
					*entry++ = 0;
				} else {
					entry = "main";
				}
				frida_device_inject_library_file_sync (rf->device,
					rf->pid, path, entry, "", &error);
				free (path);
			}
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
		case '?':
			eprintf ("Usage: .[-] [filename]  # load and run the given script into the agent\n");
			eprintf (".              list loaded plugins via r2frida.pluginRegister()\n");
			eprintf (".-foo          unload r2frida plugin via r2frida.pluginUnregister()\n");
			eprintf (". file.js      run this script in the agent side\n");
			break;
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
		if (command[0] == 'j') { // "j"
			// Example: "\j var a=Java.use('java.lang.String');var b=a.$new('findus');console.log('sinderel'+b.toString())"
			// Output: sinderelfindus
			GError *error = NULL;
			char *js;
			builder = build_request ("evaluate");
			json_builder_set_member_name (builder, "code");
			char *code = r_str_newf ("Java.perform(function(){%s;})", command + 1);
			json_builder_add_string_value (builder, code);
			free (code);
		} else if (command[0] == ' ') {
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

	if (!json_object_has_member (result, "value")) {
		return NULL;
	}
	value = json_object_get_string_member (result, "value");
	char *sys_result = NULL;
	if (value && strcmp (value, "undefined")) {
		bool is_fs_io = command[0] == 'm';
		if (is_fs_io) {
			sys_result = strdup (value);
		} else {
			io->cb_printf ("%s\n", value);
		}
	}
	json_object_unref (result);

	return sys_result;
}

static bool parse_device_id_as_uriroot(char *path, const char *arg, R2FridaLaunchOptions *lo) {
	char *slash = strchr (arg, '/');
	if (slash && !*slash) {
		slash = NULL;
	}
	if (!strcmp (path, "spawn")) {
		lo->device_id = NULL;
		lo->spawn = true;

		if (slash) {
			int first_word_len = slash - arg;
			if ((first_word_len == 3 && !strncmp (arg, "usb", 3)) ||
				(first_word_len == 7 && !strncmp (arg, "connect", 7))) {
				char * first_word = g_strndup (arg, first_word_len);
				bool result = parse_device_id_as_uriroot (first_word, slash + 1, lo);
				g_free (first_word);
				return result;
			}
		}

#if __UNIX__
		char *abspath = r_file_path (arg);
		lo->process_specifier = g_strdup (abspath? abspath: arg);
#else
		lo->process_specifier = g_strdup (arg);
#endif
		return true;
	}
	if (!strcmp (path, "attach")) {
		lo->device_id = NULL;

		if (slash) {
			int first_word_len = slash - arg;
			if ((first_word_len == 3 && !strncmp (arg, "usb", 3)) ||
				(first_word_len == 7 && !strncmp (arg, "connect", 7))) {
				char * first_word = g_strndup (arg, first_word_len);
				bool result = parse_device_id_as_uriroot (first_word, slash + 1, lo);
				g_free (first_word);
				return result;
			}
		}

		lo->process_specifier = g_strdup (arg);
		if (arg) {
			lo->pid = atopid (arg, &lo->pid_valid);
		} else {
			eprintf ("Cannot attach without arg\n");
		}
		return true;
	}
	if (!strcmp (path, "usb")) {
		char *rest = g_strdup (arg);
		char *slash = strchr (rest, '/');
		if (slash) {
			*slash++ = 0;
			lo->pid = atopid (slash, &lo->pid_valid);
			lo->device_id = rest;
			lo->process_specifier = g_strdup (slash);
		} else {
			if (*rest) {
				FridaDevice *device;
				GError *error = NULL;

				device = frida_device_manager_get_device_by_id_sync (device_manager, rest, 0, NULL, &error);
				if (device != NULL) {
					dumpProcesses (device);
					frida_unref (device);
				} else {
					eprintf ("%s: %s\n", rest, error->message);
					g_error_free (error);
				}
			} else {
				dumpDevices ();
			}
			g_free (rest);
		}
		return true;
	}
	// remote device
	if (!strcmp (path, "connect")) {
		// host:port
		lo->device_id = g_strdup (arg);
		char *slash = strchr (lo->device_id, '/');
		if (slash) {
			*slash++ = 0;
			lo->pid = atopid (slash, &lo->pid_valid);
			lo->process_specifier = g_strdup (slash);
		} else {
			eprintf ("Usage: r2 frida://connect/ip:port/pid\n");
			eprintf ("Note: no hostname resolution supported yet.\n");
		}
		return true;
	}
	return false;
}

static bool parse_target(const char *pathname, R2FridaLaunchOptions *lo) {
	const char *first_field = pathname + 8;
	if (!strcmp (first_field, "?")) {
		eprintf ("r2 frida://[action]/[target]\n");
		eprintf ("* target = process-id | process-name | app-name\n");
		eprintf ("* program = find-in-path | absolute-path\n");
		eprintf ("* device = device-id | ''\n");
		eprintf ("* peer = ip-address:port            # no hostname resolution\n");
		eprintf ("Long URIs: (new)\n");
		eprintf ("* frida://spawn/$(program)          # start a new process\n");
		eprintf ("* frida://attach/(target)           # attach to current\n");
		eprintf ("* frida://usb/$(device)/$(target)   # connect to USB device\n");
		eprintf ("* frida://remote/$(peer)/$(target)  # connect to remote frida-server\n");
		eprintf ("* frida://spawn/usb/$(device)/$(program)\n");
		eprintf ("* frida://attach/usb/$(device)/$(target)\n");
		eprintf ("Short URIs: (old)\n");
		eprintf ("* frida://$(target)                 # local process attach\n");
		eprintf ("* frida://$(device)/$(target)       # attach device\n");
		eprintf ("* frida:///$(program)               # spawn local\n");
		eprintf ("* frida://$(device)//$(program)     # spawn device\n");
		eprintf ("Bonus Track:\n");
		eprintf ("* frida://                          # list local processes\n");
		eprintf ("* frida://0                         # attach to frida-helper\n");
		eprintf ("* frida:///usr/local/bin/rax2       # abspath to spawn\n");
		eprintf ("* frida://usb/                      # list devices\n");
		eprintf ("* frida://usb//                     # list remote processes\n");
		eprintf ("* frida://usb//0                    # attach to remote frida-helper\n");
		eprintf ("* frida://usb//1234                 # list devices\n");
		eprintf ("* frida://usb/$(peer)               # list process-names\n");
		eprintf ("Environment:\n");
		eprintf ("R2FRIDA_DISABLE_V8                  # if set, use duktape instead of v8\n");
		eprintf ("R2FRIDA_AGENT_SCRIPT                # path to file of the r2frida agent\n");
		return false;
	}
	lo->spawn = false;
	const char *second_field;
	if (*first_field == '/' || !strncmp (first_field, "./", 2)) {
		// frida:///path/to/file
		lo->spawn = true;
		second_field = NULL;
	} else {
		// frida://device/...
		second_field = strchr (first_field, '/');
	}

	if (!second_field) {
		// frida://process or frida:///path/to/file
		lo->device_id = NULL;
		lo->process_specifier = g_strdup (first_field);
		return true;
	}
	second_field++;

	char *first_word = g_strndup (first_field, second_field - first_field - 1);

	if (parse_device_id_as_uriroot (first_word, second_field, lo)) {
		g_free (first_word);
		return true;
	}
	lo->device_id = first_word;

	if (*second_field == '/') {
		// frida://device//com.your.app
		lo->spawn = true;
		second_field++;
	}

	// frida://device/process or frida://device//com.your.app
	lo->process_specifier = g_strdup (second_field);
	return true;
}

static bool resolve_device(FridaDeviceManager *manager, const char *device_id, FridaDevice **device) {
	GError *error = NULL;

	if (device_id != NULL) {
		if (!*device_id) { // "frida://attach/usb//Safari"
			*device = frida_device_manager_get_device_by_type_sync (manager, FRIDA_DEVICE_TYPE_USB, 0, NULL, &error);
		} else if (strchr (device_id, ':')) { // host:port
			*device = frida_device_manager_add_remote_device_sync (manager, device_id, &error);
		} else {
			*device = frida_device_manager_get_device_by_id_sync (manager, device_id, 0, NULL, &error);
		}
	} else { // "frida://
		*device = frida_device_manager_get_device_by_type_sync (manager, FRIDA_DEVICE_TYPE_LOCAL, 0, NULL, &error);
	}

	if (error != NULL) {
		eprintf ("%s\n", error->message);
		g_error_free (error);
		return false;
	}

	return true;
}

static bool resolve_process(FridaDevice *device, R2FridaLaunchOptions *lo) {
	GError *error = NULL;

	if (lo->process_specifier) {
		if (*lo->process_specifier) {
			int number = atopid (lo->process_specifier, &lo->pid_valid);
			if (lo->pid_valid) {
				lo->pid = number;
				return true;
			}
		} else {
			dumpProcesses (device);
		}
	} else if (lo->pid_valid) {
		return true;
	}

	if (!lo->process_specifier) {
		return false;
	}

	FridaProcess *process = frida_device_get_process_by_name_sync (
		device, lo->process_specifier, 0, NULL, &error);
	if (error != NULL) {
		eprintf ("%s\n", error->message);
		g_error_free (error);
		return false;
	}

	lo->pid = frida_process_get_pid (process);
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

static void on_detached(FridaSession *session, FridaSessionDetachReason reason, FridaCrash *crash, gpointer user_data) {
	RIOFrida *rf = user_data;
	rf->detached = true;
	rf->detach_reason = reason;
	eprintf ("DetachReason: %s\n", detachReasonAsString (rf));
	if (crash) {
		const char *crash_report = frida_crash_get_report (crash);
		free (rf->crash_report);
		rf->crash_report = strdup (crash_report);
		eprintf ("CrashReport: %s\n", crash_report);
	}
	g_mutex_lock (&rf->lock);
	rf->crash = (crash != NULL) ? g_object_ref (crash) : NULL;
	g_cond_signal (&rf->cond);
	g_mutex_unlock (&rf->lock);
}

static void on_cmd(RIOFrida *rf, JsonObject *cmd_stanza) {
	g_mutex_lock (&rf->lock);
	g_assert (!rf->pending_cmd);
	if (cmd_stanza) {
		rf->pending_cmd = pending_cmd_create (cmd_stanza);
	} else {
		rf->pending_cmd = R_NEW0 (RFPendingCmd);
	}
	g_cond_signal (&rf->cond);
	g_mutex_unlock (&rf->lock);
}

static void on_message(FridaScript *script, const char *raw_message, GBytes *data, gpointer user_data) {
	RIOFrida *rf = user_data;
	JsonNode *message = json_from_string (raw_message, NULL);
	g_assert (message != NULL);
	JsonObject *root = json_node_get_object (message);
	const char *type = json_object_get_string_member (root, "type");

	if (type && !strcmp (type, "send")) {
		JsonNode *payload_node = json_object_get_member (root, "payload");
		JsonNodeType type = json_node_get_node_type (payload_node);
		if (type == JSON_NODE_OBJECT) {
			JsonObject *payload = json_object_ref (json_object_get_object_member (root, "payload"));
			const char *name = json_object_get_string_member (payload, "name");
			if (name && !strcmp (name, "reply")) {
				JsonNode *stanza_node = json_object_get_member (payload, "stanza");
				if (stanza_node) {
					JsonNodeType stanza_type = json_node_get_node_type (stanza_node);
					if (stanza_type == JSON_NODE_OBJECT) {
						on_stanza (rf, json_object_ref (json_object_get_object_member (payload, "stanza")), data);
					} else {
						eprintf ("Bug in the agent, cannot find stanza in the message: %s\n", raw_message);
					}
				} else {
					eprintf ("Bug in the agent, expected an object: %s\n", raw_message);
				}
			} else if (!strcmp (name, "cmd")) {
				on_cmd (rf, json_object_get_object_member (payload, "stanza"));
			}
			json_object_unref (payload);
		} else {
			eprintf ("Bug in the agent, expected an object: %s\n", raw_message);
		}
	} else if (!strcmp (type, "log")) {
		eprintf ("%s\n", json_object_get_string_member (root, "payload"));
	} else {
		eprintf ("Unhandled message: %s\n", raw_message);
	}

	json_node_unref (message);
}

static void dumpDevices(void) {
	GString *dump;
	FridaDeviceList *list;
	GArray *devices;
	gint num_devices, i;
	guint id_column_width, type_column_width, name_column_width;
	GEnumClass *type_enum;

	dump = g_string_sized_new (256);

	list = frida_device_manager_enumerate_devices_sync (device_manager, NULL);
	num_devices = frida_device_list_size (list);

	devices = g_array_sized_new (FALSE, FALSE, sizeof (FridaDevice *), num_devices);
	for (i = 0; i != num_devices; i++) {
		FridaDevice *device = frida_device_list_get (list, i);
		g_array_append_val (devices, device);
		g_object_unref (device); /* borrow it */
	}
	g_array_sort (devices, compareDevices);

	id_column_width = 0;
	type_column_width = 6;
	name_column_width = 0;
	for (i = 0; i != num_devices; i++) {
		FridaDevice *device = g_array_index (devices, FridaDevice *, i);

		id_column_width = MAX (strlen (frida_device_get_id (device)), id_column_width);
		name_column_width = MAX (strlen (frida_device_get_name (device)), name_column_width);
	}

	g_string_append_printf (dump, "%-*s  %-*s  %s\n",
		id_column_width, "Id",
		type_column_width, "Type",
		"Name");

	for (i = 0; i != id_column_width; i++) {
		g_string_append_c (dump, '-');
	}
	g_string_append (dump, "  ");
	for (i = 0; i != type_column_width; i++) {
		g_string_append_c (dump, '-');
	}
	g_string_append (dump, "  ");
	for (i = 0; i != name_column_width; i++) {
		g_string_append_c (dump, '-');
	}
	g_string_append_c (dump, '\n');

	type_enum = g_type_class_ref (FRIDA_TYPE_DEVICE_TYPE);

	for (i = 0; i != num_devices; i++) {
		FridaDevice *device;
		GEnumValue *type;

		device = g_array_index (devices, FridaDevice *, i);

		type = g_enum_get_value (type_enum, frida_device_get_dtype (device));

		g_string_append_printf (dump, "%-*s  %-*s  %s\n",
			id_column_width, frida_device_get_id (device),
			type_column_width, type->value_nick,
			frida_device_get_name (device));
	}

	r_cons_printf ("%s\n", dump->str);

	g_type_class_unref (type_enum);
	frida_unref (list);

	g_string_free (dump, TRUE);
}

static void dumpApplications(FridaDevice *device) {
	GString *dump;
	FridaApplicationList *list;
	GArray *applications;
	gint num_applications, i;
	GError *error;
	guint pid_column_width, name_column_width;

	dump = g_string_sized_new (8192);

	error = NULL;
        list = frida_device_enumerate_applications_sync (device, &error);
	if (error != NULL) {
		eprintf ("%s\n", error->message);
		goto beach;
	}
	num_applications = frida_application_list_size (list);

	applications = g_array_sized_new (FALSE, FALSE, sizeof (FridaApplication *), num_applications);
	for (i = 0; i != num_applications; i++) {
		FridaApplication *application = frida_application_list_get (list, i);
		g_array_append_val (applications, application);
		g_object_unref (application); /* borrow it */
	}
	// TODO: g_array_sort (applications, compareProcesses);

	pid_column_width = 0;
	name_column_width = 0;
	for (i = 0; i != num_applications; i++) {
		FridaApplication *application;
		gchar *pid_str;

		application = g_array_index (applications, FridaApplication *, i);

		pid_str = g_strdup_printf ("%u", frida_application_get_pid (application));
		pid_column_width = MAX (strlen (pid_str), pid_column_width);
		g_free (pid_str);

		name_column_width = MAX (strlen (frida_application_get_name (application)), name_column_width);
	}

	g_string_append_printf (dump, "%-*s  %s\n",
		pid_column_width, "PID",
		"Name");

	for (i = 0; i != pid_column_width; i++) {
		g_string_append_c (dump, '-');
	}
	g_string_append (dump, "  ");
	for (i = 0; i != name_column_width; i++) {
		g_string_append_c (dump, '-');
	}
	g_string_append_c (dump, '\n');

	for (i = 0; i != num_applications; i++) {
		FridaApplication *application = g_array_index (applications, FridaApplication*, i);

		g_string_append_printf (dump, "%*u  %s\n",
			pid_column_width, frida_application_get_pid (application),
			frida_application_get_name (application));
	}

	r_cons_printf ("%s\n", dump->str);

beach:
	g_clear_error (&error);
	g_clear_object (&list);

	g_string_free (dump, TRUE);
}

static void dumpProcesses(FridaDevice *device) {
	GString *dump;
	FridaProcessList *list;
	GArray *processes;
	gint num_processes, i;
	GError *error;
	guint pid_column_width, name_column_width;

	dump = g_string_sized_new (8192);

	error = NULL;
	list = frida_device_enumerate_processes_sync (device, &error);
	if (error != NULL) {
		eprintf ("%s\n", error->message);
		goto beach;
	}
	num_processes = frida_process_list_size (list);

	processes = g_array_sized_new (FALSE, FALSE, sizeof (FridaProcess *), num_processes);
	for (i = 0; i != num_processes; i++) {
		FridaProcess *process = frida_process_list_get (list, i);
		g_array_append_val (processes, process);
		g_object_unref (process); /* borrow it */
	}
	g_array_sort (processes, compareProcesses);

	pid_column_width = 0;
	name_column_width = 0;
	for (i = 0; i != num_processes; i++) {
		FridaProcess *process;
		gchar *pid_str;

		process = g_array_index (processes, FridaProcess *, i);

		pid_str = g_strdup_printf ("%u", frida_process_get_pid (process));
		pid_column_width = MAX (strlen (pid_str), pid_column_width);
		g_free (pid_str);

		name_column_width = MAX (strlen (frida_process_get_name (process)), name_column_width);
	}

	g_string_append_printf (dump, "%-*s  %s\n",
		pid_column_width, "PID",
		"Name");

	for (i = 0; i != pid_column_width; i++) {
		g_string_append_c (dump, '-');
	}
	g_string_append (dump, "  ");
	for (i = 0; i != name_column_width; i++) {
		g_string_append_c (dump, '-');
	}
	g_string_append_c (dump, '\n');

	for (i = 0; i != num_processes; i++) {
		FridaProcess *process = g_array_index (processes, FridaProcess *, i);

		g_string_append_printf (dump, "%*u  %s\n",
			pid_column_width, frida_process_get_pid (process),
			frida_process_get_name (process));
	}

	r_cons_printf ("%s\n", dump->str);

beach:
	g_clear_error (&error);
	g_clear_object (&list);

	g_string_free (dump, TRUE);
}

static gint compareDevices(gconstpointer element_a, gconstpointer element_b) {
	FridaDevice *a = *(FridaDevice **) element_a;
	FridaDevice *b = *(FridaDevice **) element_b;
	gint score_a, score_b;

	score_a = computeDeviceScore (a);
	score_b = computeDeviceScore (b);
	if (score_a != score_b) {
		return score_b - score_a;
	}

	return strcmp (frida_device_get_name (a), frida_device_get_name (b));
}

static gint compareProcesses(gconstpointer element_a, gconstpointer element_b) {
	FridaProcess *a = *(FridaProcess **) element_a;
	FridaProcess *b = *(FridaProcess **) element_b;
	gint score_a, score_b, name_equality;

	score_a = computeProcessScore (a);
	score_b = computeProcessScore (b);
	if (score_a != score_b) {
		return score_b - score_a;
	}

	name_equality = strcmp (frida_process_get_name (a), frida_process_get_name (b));
	if (name_equality != 0) {
		return name_equality;
	}

	return (gint) frida_process_get_pid (a) - (gint) frida_process_get_pid (b);
}

static gint computeDeviceScore(FridaDevice *device) {
	switch (frida_device_get_dtype (device)) {
	case FRIDA_DEVICE_TYPE_LOCAL:
		return 3;
	case FRIDA_DEVICE_TYPE_USB:
		return 2;
	case FRIDA_DEVICE_TYPE_REMOTE:
		return 1;
	}
}

static gint computeProcessScore(FridaProcess *process) {
	return (frida_process_get_small_icon (process) != NULL) ? 1 : 0;
}

static int atopid(const char *maybe_pid, bool *valid) {
	char *endptr;
	int number = strtol (maybe_pid, &endptr, 10);
	*valid = endptr == NULL || (endptr - maybe_pid) == strlen (maybe_pid);
	return number;
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
//	.isdbg = true // this requires 'dL io' and some fixes in !!!
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_frida,
	.version = R2_VERSION
};
#endif
