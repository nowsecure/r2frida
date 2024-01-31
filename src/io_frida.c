/* radare2 - MIT - Copyright 2016-2023 - pancake, oleavr, mrmacete */

#define R_LOG_ORIGIN "r2frida"

#include <r_core.h>
#include <r_io.h>
#include "frida-core.h"
#include "../config.h"

#if R2_VERSION_NUMBER >= 50609
#define COREBIND(x) (x)->coreb
#else
#define COREBIND(x) (x)->corebind
#endif

typedef struct {
	const char *cmd_string;
	ut64 serial;
	JsonObject *_cmd_json;
} RFPendingCmd;

typedef struct {
	char *device_id;
	char *process_specifier;
	guint pid;
	bool pid_valid;
	bool spawn;
	bool run;
} R2FridaLaunchOptions;

typedef struct {
	FridaDevice *device;
	FridaSession *session;
	FridaScript *script;
	GCancellable *cancellable;

	guint pid;
	GMutex lock;
	GCond cond;
	bool suspended;
	bool suspended2;
	volatile bool detached;
	volatile FridaSessionDetachReason detach_reason;
	FridaCrash *crash;
	volatile bool received_reply;
	JsonObject *reply_stanza;
	GBytes *reply_bytes;
	RCore *r2core;
	RFPendingCmd * pending_cmd;
	char *crash_report;
	RIO *io;
	RSocket *s;
	gulong onmsg_handler;
	gulong ondtc_handler;
	FridaDeviceManager *device_manager;
	RStrBuf *sb;
	bool inputmode;
} RIOFrida;

typedef enum {
	PROCESSES,
	APPLICATIONS,
	DEVICES,
} R2FridaListType;

#define RIOFRIDA_DEV(x) (((RIOFrida*)x->data)->device)
#define RIOFRIDA_SESSION(x) (((RIOFrida*)x->data)->session)

static FridaDevice *get_device_manager(FridaDeviceManager *manager, const char *type, GCancellable *cancellable, GError **error);
static bool resolve_target(RIOFrida *rf, const char *pathname, R2FridaLaunchOptions *lo, GCancellable *cancellable);
static bool resolve_device(RIOFrida *rf, const char *device_id, FridaDevice **device, GCancellable *cancellable);
static bool resolve_process(FridaDevice *device, R2FridaLaunchOptions *lo, GCancellable *cancellable);
static JsonBuilder *build_request(const char *type);
static void add_offset_parameter(JsonBuilder *builder, ut64 off);
static JsonObject *perform_request(RIOFrida *rf, JsonBuilder *builder, GBytes *data, GBytes **bytes);
static RFPendingCmd * pending_cmd_create(JsonObject * cmd_json);
static void pending_cmd_free(RFPendingCmd * pending_cmd);
static void perform_request_unlocked(RIOFrida *rf, JsonBuilder *builder, GBytes *data, GBytes **bytes);
static void exec_pending_cmd_if_needed(RIOFrida * rf);
static char *__system(RIO *io, RIODesc *fd, const char *command);
static char *resolve_package_name_by_process_name(FridaDevice *device, GCancellable *cancellable, const char *appname);
static char *resolve_process_name_by_package_name(FridaDevice *device, GCancellable *cancellable, const char *bundleid);
static int atopid(const char *maybe_pid, bool *valid);

// event handlers
static void on_message(FridaScript *script, const char *message, GBytes *data, gpointer user_data);
static void on_detached(FridaSession *session, FridaSessionDetachReason reason, FridaCrash *crash, gpointer user_data);

static void dumpDevices(RIOFrida *rf, GCancellable *cancellable);
static void dumpProcesses(FridaDevice *device, GCancellable *cancellable);
static int dumpApplications(FridaDevice *device, GCancellable *cancellable);
static gint compareDevices(gconstpointer element_a, gconstpointer element_b);
static gint compareProcesses(gconstpointer element_a, gconstpointer element_b);
static gint computeDeviceScore(FridaDevice *device);
static void print_list(R2FridaListType type, GArray *items, gint num_items);

extern RIOPlugin r_io_plugin_frida;

static const char * const helpmsg = ""\
	"r2 frida://[action]/[link]/[device]/[target]\n"
	"* action = list | apps | attach | spawn | launch\n"
	"* link   = local | usb | remote host:port\n"
	"* device = '' | host:port | device-id\n"
	"* target = pid | appname | process-name | program-in-path | abspath\n"
	"Local:\n"
	"* frida://?                        # show this help\n"
	"* frida://                         # list local processes\n"
	"* frida://0                        # attach to frida-helper (no spawn needed)\n"
	"* frida:///usr/local/bin/rax2      # abspath to spawn\n"
	"* frida://rax2                     # same as above, considering local/bin is in PATH\n"
	"* frida://spawn/$(program)         # spawn a new process in the current system\n"
	"* frida://attach/(target)          # attach to target PID in current host\n"
	"USB:\n"
	"* frida://list/usb//               # list processes in the first usb device\n"
	"* frida://apps/usb//               # list apps in the first usb device\n"
	"* frida://attach/usb//12345        # attach to given pid in the first usb device\n"
	"* frida://spawn/usb//appname       # spawn an app in the first resolved usb device\n"
	"* frida://launch/usb//appname      # spawn+resume an app in the first usb device\n"
	"Remote:\n"
	"* frida://attach/remote/10.0.0.3:9999/558 # attach to pid 558 on tcp remote frida-server\n"
	"Environment: (Use the `%` command to change the environment at runtime)\n"
	"  R2FRIDA_SCRIPTS_DIR="R2_DATDIR"/r2frida/scripts\n"
	"  R2FRIDA_SCRIPTS_DIR=~/.local/share/radare2/r2frida/scripts\n"
	"  R2FRIDA_SAFE_IO=0|1              # Workaround a Frida bug on Android/thumb\n"
	"  R2FRIDA_DEBUG=0|1                # Used to trace internal r2frida C and JS calls\n"
	"  R2FRIDA_RUNTIME=qjs|v8           # Select the javascript engine to use in the agent side (v8 is default)\n"
	"  R2FRIDA_DEBUG_URI=0|1            # Trace uri parsing code and exit before doing any action\n"
	"  R2FRIDA_COMPILER_DISABLE=0|1     # Disable the new frida typescript compiler (`:. foo.ts`)\n"
	"  R2FRIDA_AGENT_SCRIPT=[file]      # path to file of the r2frida agent\n";

#define src__agent__js r_io_frida_agent_code

static const gchar r_io_frida_agent_code[] = {
#include "_agent.h"
};

static bool r2f_debug_uri(void) {
	return r_sys_getenv_asbool ("R2FRIDA_DEBUG_URI");
}

static bool r2f_compiler(void) {
	return !r_sys_getenv_asbool ("R2FRIDA_COMPILER_DISABLE");
}

static FridaScriptRuntime r2f_jsruntime(void) {
	const FridaScriptRuntime default_runtime = FRIDA_SCRIPT_RUNTIME_QJS;
	char *engine = r_sys_getenv ("R2FRIDA_RUNTIME");
	if (engine) {
		const bool isqjs = !strcmp (engine, "qjs");
		free (engine);
		return isqjs
			? FRIDA_SCRIPT_RUNTIME_QJS
			: FRIDA_SCRIPT_RUNTIME_V8;
	}
	return default_runtime;
}

static void resume(RIOFrida *rf) {
	if (!rf) {
		return;
	}
	if (rf->suspended2) {
		// send breakpoint-action
		rf->suspended2 = false;
		const char *message = "{\"type\": \"breakpoint-action\",\"action\":\"resume\"}";
		frida_script_post (rf->script, message, NULL);
		return;
	}
	GError *error = NULL;
	frida_device_resume_sync (rf->device, rf->pid, rf->cancellable, &error);
	if (error) {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			rf->io->cb_printf ("frida_device_resume_sync: %s\n", error->message);
		}
		g_clear_error (&error);
	} else {
		rf->suspended = false;
		R_LOG_INFO ("resumed spawned process");
	}
}

static RIOFrida *r_io_frida_new(RIO *io) {
	if (!io) {
		return NULL;
	}
	RIOFrida *rf = R_NEW0 (RIOFrida);
	if (!rf) {
		return NULL;
	}

	rf->cancellable = g_cancellable_new (); // TODO: call cancel() when shutting down
	rf->s = r_socket_new (false);
	rf->sb = r_strbuf_new ("");
	rf->detached = false;
	rf->detach_reason = 0;
	rf->io = io;
	rf->crash = NULL;
	rf->crash_report = NULL;
	rf->received_reply = false;
	rf->r2core = COREBIND (io).core;
	if (!rf->r2core) {
		R_LOG_ERROR ("r2frida cannot find the RCore instance from IO->user");
		free (rf);
		return NULL;
	}
	rf->suspended = false;

	return rf;
}

static bool request_safe_io(RIOFrida *rf, bool doset) {
	JsonBuilder *builder = build_request (doset? "safeio": "unsafeio");
	JsonObject *result = perform_request (rf, builder, NULL, NULL);
	if (!result) {
		return false;
	}
	json_object_unref (result);
	return true;
}

static R2FridaLaunchOptions *r2frida_launchopt_new(const char *pathname) {
	R2FridaLaunchOptions *lo = R_NEW0 (R2FridaLaunchOptions);
	if (lo) {
		// lo
	}
	return lo;
}

static void r2frida_launchopt_free(R2FridaLaunchOptions *lo) {
	if (lo) {
		g_free (lo->device_id);
		g_free (lo->process_specifier);
		free (lo);
	}
}

static void r_io_frida_free(RIOFrida *rf) {
	if (!rf) {
		return;
	}
	if (rf->script && rf->onmsg_handler) {
		g_signal_handler_disconnect (rf->script, rf->onmsg_handler);
	}
	if (rf->session && rf->ondtc_handler) {
		g_signal_handler_disconnect (rf->session, rf->ondtc_handler);
	}
	r_socket_free (rf->s);
	free (rf->crash_report);
	r_strbuf_free (rf->sb);
	g_clear_object (&rf->crash);
	g_clear_object (&rf->script);
	g_clear_object (&rf->session);
	g_clear_object (&rf->device);

	if (rf->device_manager) {
		if (!rf->detached) {
			frida_device_manager_close_sync (rf->device_manager, NULL, NULL);
		}
		g_object_unref (rf->device_manager);
		rf->device_manager = NULL;
	}

	g_object_unref (rf->cancellable);
	memset (rf, 0, sizeof (RIOFrida));
	free (rf);
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

static bool user_wants_safe_io(FridaDevice *device) {
	bool SAFE_IO_required = false;
#if 0
	/* Requesting safe_io on iOS15 until https://github.com/frida/frida-gum/commit/72c5c84a424e40336489ee0624e46a7ff31807b8 */
	GError *error = NULL;
	GHashTable * params;
	GVariant * os;
	gchar * version;
	params = frida_device_query_system_parameters_sync (device, NULL, &error);
	if (!error) {
		os = g_hash_table_lookup (params, "os");
		g_variant_lookup (os, "version", "s", &version);
		g_hash_table_unref (params);
		SAFE_IO_required = r_str_startswith(version, "15") || r_str_startswith(version, "16");
		g_free (version);
	}
#endif
	return r_sys_getenv_asbool ("R2FRIDA_SAFE_IO") || SAFE_IO_required;
}

static bool __close(RIODesc *fd) {
	if (!fd || !fd->data) {
		return false;
	}
	R_LOG_DEBUG ("close");
	RIOFrida *rf = fd->data;
	g_mutex_lock (&rf->lock);
	rf->detached = true;
	resume (rf);
	g_cond_signal (&rf->cond);
	g_mutex_unlock (&rf->lock);
	r_io_frida_free (fd->data);
	fd->data = NULL;
	return true;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	GBytes *bytes = NULL;
	gsize n = 0;
	r_return_val_if_fail (io && fd && fd->data && buf && count > 0, -1);

	R_LOG_DEBUG ("read %d @ 0x%08"PFMT64x, count, io->off);
	RIOFrida *rf = fd->data;

	JsonBuilder *builder = build_request ("read");
	add_offset_parameter (builder, io->off);
	json_builder_set_member_name (builder, "count");
	json_builder_add_int_value (builder, count);
	json_builder_set_member_name (builder, "fast");
	json_builder_add_boolean_value (builder, false);

	JsonObject *result = perform_request (rf, builder, NULL, &bytes);
	if (!result) {
		return -1;
	}
	if (bytes) {
		gconstpointer data = g_bytes_get_data (bytes, &n);
		if (data && buf) {
			memcpy (buf, data, R_MIN (n, count));
		}
	} else {
		memset (buf, 0xff, count);
	}

	json_object_unref (result);
	g_bytes_unref (bytes);

	return n;
}

static bool __eternalizeScript(RIOFrida *rf, const char *fileName) {
	char *agent_code = r_file_slurp (fileName, NULL);
	if (!agent_code) {
		R_LOG_ERROR ("Cannot load '%s'", fileName);
		return false;
	}
	GError *error;
	FridaScriptOptions * options = frida_script_options_new ();
	frida_script_options_set_name (options, "eternalized-script");
	FridaScriptRuntime runtime = r2f_jsruntime ();
	frida_script_options_set_runtime (options, runtime);
	FridaScript *script = frida_session_create_script_sync (rf->session,
		agent_code, options, rf->cancellable, &error);
	if (!script) {
		R_LOG_ERROR ("%s", error->message);
		return false;
	}
	frida_script_load_sync (script, NULL, NULL);
	frida_script_eternalize_sync (script, NULL, NULL);
	g_clear_object (&script);
	return true;
}

static int on_compiler_diagnostics (void *user, GVariant *diagnostics) {
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

static ut64 __lseek(RIO* io, RIODesc *fd, ut64 offset, int whence) {
	R_LOG_DEBUG ("lseek %d @ 0x%08"PFMT64x, whence, offset);
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
	if (!fd || !fd->data) {
		return -1;
	}

	R_LOG_DEBUG ("write %d @ 0x%08"PFMT64x, io->off, count);
	RIOFrida *rf = fd->data;

	JsonBuilder *builder = build_request ("write");
	add_offset_parameter (builder, io->off);

	JsonObject *result = perform_request (rf, builder, g_bytes_new (buf, count), NULL);
	if (!result) {
		return -1;
	}
	json_object_unref (result);

	return count;
}

static bool __resize(RIO *io, RIODesc *fd, ut64 count) {
	return false;
}

static char *__system_continuation(RIO *io, RIODesc *fd, const char *command) {
	JsonBuilder *builder;
	JsonObject *result;
	R_LOG_DEBUG ("system_continuation (%s)", command);

	if (!strcmp (command, "help") || !strcmp (command, "h") || !strcmp (command, "?")) {
		// TODO: move this into the .js
		io->cb_printf ("r2frida commands are prefixed with `:` (alias for `=!`).\n"
		":. script                   Run script\n"
		":  frida-expression         Run given expression inside the agent\n"
		":/[x][j] <string|hexpairs>  Search hex/string pattern in memory ranges (see search.in=?)\n"
		":/v[1248][j] value          Search for a value honoring `e cfg.bigendian` of given width\n"
		":/w[j] string               Search wide string\n"
		":<space> code..             Evaluate Cycript code\n"
		":?                          Show this help\n"
		":?e message                 Show message like ?e but from the agent\n"
		":?E title message           Show UIAlert dialog with given title and message\n"
		":?V                         Show target Frida version\n"
		":chcon file                 Change SELinux context (dl might require this)\n"
		":d.                         Start the chrome tools debugger\n"
		":dbn [addr|-addr]           List set, or delete a breakpoint\n"
		":dbnc [addr] [command]      Associate an r2 command to an r2frida breakpoint\n"
		":db (<addr>|<sym>)          List or place breakpoint (DEPRECATED)\n"
		":db- (<addr>|<sym>)|*       Remove breakpoint(s) (DEPRECATED)\n"
		":dc                         Continue breakpoints or resume a spawned process\n"
		":dd[j-][fd] ([newfd])       List, dup2 or close filedescriptors (ddj for JSON)\n"
		":di[0,1,-1,i,s,v] [addr]    Intercepts and replace return value of address without calling the function\n"
		":dif[0,1,-1,i,s] [addr]     Intercepts return value of address after calling the function\n"
		":dk ([pid]) [sig]           Send specific signal to specific pid in the remote system\n"
		":dkr                        Print the crash report (if the app has crashed)\n"
		":dl libname                 Dlopen a library (Android see chcon)\n"
		":dl2 libname [main]         Inject library using Frida's >= 8.2 new API\n"
		":dlf path                   Load a Framework Bundle (iOS) given its path\n"
		":dlf- path                  Unload a Framework Bundle (iOS) given its path\n"
		":dm[.|j|*]                  Show memory regions\n"
		":dma <size>                 Allocate <size> bytes on the heap, address is returned\n"
		":dma- (<addr>...)           Kill the allocations at <addr> (or all of them without param)\n"
		":dmad <addr> <size>         Allocate <size> bytes on the heap, copy contents from <addr>\n"
		":dmal                       List live heap allocations created with dma[s]\n"
		":dmas <string>              Allocate a string initiated with <string> on the heap\n"
		":dmaw <string>              Allocate a widechar string initiated with <string> on the heap\n"
		":dmh                        List all heap allocated chunks\n"
		":dmh*                       Export heap chunks and regions as r2 flags\n"
		":dmhj                       List all heap allocated chunks in JSON\n"
		":dmhm                       Show which maps are used to allocate heap chunks\n"
		":dmm                        List all named squashed maps\n"
		":dmp <addr> <size> <perms>  Change page at <address> with <size>, protection <perms> (rwx)\n"
		":dp                         Show current pid\n"
		":dpt                        Show threads\n"
		":dr                         Show thread registers (see dpt)\n"
		":dt (<addr>|<sym>) ..       Trace list of addresses or symbols\n"
		":dt- (<addr>|<sym>)         Clear trace\n"
		":dt-*                       Clear all tracing\n"
		":dt.                        Trace at current offset\n"
		":dtf <addr> [fmt]           Trace address with format (^ixzO) (see dtf?)\n"
		":dth (addr|sym)(x:0 y:1 ..) Define function header (z=str,i=int,v=hex barray,s=barray)\n"
		":dtl[-*] [msg]              debug trace log console, useful to .:T*\n"
		":dtr <addr> (<regs>...)     Trace register values\n"
		":dts[*j] seconds            Trace all threads for given seconds using the stalker\n"
		":dtsf[*j] [sym|addr]        Trace address or symbol using the stalker (Frida >= 10.3.13)\n"
		":dxc [sym|addr] [args..]    Call the target symbol with given args\n"
		":e[?] [a[=b]]               List/get/set config evaluable vars\n"
		":env [k[=v]]                Get/set environment variable\n"
		":eval code..                Evaluate Javascript code in agent side\n"
		":fd[*j] <address>           Inverse symbol resolution\n"
		":i                          Show target information\n"
		":iE[*] <lib>                Same as is, but only for the export global ones\n"
		":iS[*]                      List sections\n"
		":iS.                        Show section name at current address\n"
		":iSj                        List sections in Json format\n"
		":iSS[*]                     List segments\n"
		":iSS.                       Show segment name at current address\n"
		":iSSj                       List segments in Json format\n"
		":ic <class>                 List Objective-C/Android Java classes, or methods of <class>\n"
		":ii[*]                      List imports\n"
		":il                         List libraries\n"
		":ip <protocol>              List Objective-C protocols or methods of <protocol>\n"
		":is[*] <lib>                List symbols of lib (local and global ones)\n"
		":isa[*] (<lib>) <sym>       Show address of symbol\n"
		":j java-expression          Run given expression inside a Java.perform(function(){}) block\n"
		":r [r2cmd]                  Run r2 command using r_core_cmd_str API call (use 'dl libr2.so)\n"
		":t [swift-module-name]      Show structs, enums, classes and protocols for a module (see swift: prefix)\n"
		);
		return NULL;
	}

	RIOFrida *rf = fd->data;

	/* update state (seek and suspended) in agent */
	{
		JsonBuilder *builder = build_request ("state");
		add_offset_parameter (builder, io->off);
		json_builder_set_member_name (builder, "suspended");
		json_builder_add_boolean_value (builder, rf->suspended);
		JsonObject *result = perform_request (rf, builder, NULL, NULL);
		if (result) {
			json_object_unref (result);
		} else if (r_str_startswith (command, "dkr")) {
			// let it pass
		} else {
			return NULL;
		}
	}

	if (R_STR_ISEMPTY (command)) {
		R_LOG_DEBUG ("empty command (.:i*)");
		r_core_cmd0 (rf->r2core, ".:i*");
		return NULL;
	} else if (r_str_startswith (command, "%")) {
		eprintf ("%s\n", helpmsg);
		return false;
	} else if (r_str_startswith (command, "o/")) {
		r_core_cmd0 (rf->r2core, "?E Yay!");
		return NULL;
	} else if (r_str_startswith (command, "d.")) {
#if WANT_SESSION_DEBUGGER
		int port = 0; // 9229
		if (command[2] == ' ') {
			port = r_num_math (NULL, r_str_trim_head_ro (command + 3));
		}
		GError *error = NULL;
#if FRIDA_VERSION_MAJOR >= 16
		frida_script_enable_debugger_sync (rf->script, port, rf->cancellable, &error);
#else
		frida_session_enable_debugger_sync (rf->session, port, rf->cancellable, &error);
#endif
		if (error) {
			if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
				R_LOG_ERROR ("frida_session_enable_debugger_sync error: %s", error->message);
			}
			g_error_free (error);
		}
#else
		R_LOG_WARN ("This build of r2frida doesn't support the Chrome debugger");
#endif
		return NULL;
	} else if (!strncmp (command, "dtf?", 4)) {
		io->cb_printf ("Usage: dtf [format] || dtf [addr] [fmt]\n");
		io->cb_printf ("  ^  = trace onEnter instead of onExit\n");
		io->cb_printf ("  %%  = format return value (only on onLeave)\n");
		io->cb_printf ("  +  = show backtrace on trace\n");
		io->cb_printf (" p/x = show pointer in hexadecimal\n");
		io->cb_printf ("  c  = show value as a string (char)\n");
		io->cb_printf ("  i  = show decimal argument\n");
		io->cb_printf ("  z  = show pointer to string\n");
		io->cb_printf ("  w  = show pointer to UTF-16 string\n");
		io->cb_printf ("  a  = show pointer to ANSI string\n");
		io->cb_printf ("  h  = hexdump from pointer (optional length, h16 to dump 16 bytes)\n");
		io->cb_printf ("  H  = hexdump from pointer (optional position of length argument, H1 to dump args[1] bytes)\n");
		io->cb_printf ("  s  = show string in place\n");
		io->cb_printf ("  Z  = untrusted null terminated string (like z)\n");
		io->cb_printf ("  S  = pointer to string\n");
		io->cb_printf ("  O  = show pointer to ObjC object\n");
	} else if (!strncmp (command, "e?", 2)) {
		io->cb_printf ("Usage: e [var[=value]]Evaluable vars\n");
		io->cb_printf ("  patch.code      = true\n");
		io->cb_printf ("  search.in       = perm:r--\n");
		io->cb_printf ("  search.quiet    = false\n");
		io->cb_printf ("  stalker.event   = compile\n");
		io->cb_printf ("  stalker.timeout = 300\n");
		io->cb_printf ("  stalker.in      = raw\n");
	// fails to aim at seek workarounding hostCmd
	} else if (r_str_startswith (command, "s  ")) {
		if (rf && rf->r2core) {
			r_core_cmdf (rf->r2core, "s %s", command + 2);
		} else {
			R_LOG_ERROR ("Invalid r2 core instance");
		}
		return NULL;
	} else if (r_str_startswith (command, "dkr")) {
		io->cb_printf ("DetachReason: %s\n", detachReasonAsString (rf));
		if (rf->crash_report) {
			io->cb_printf ("%s\n", rf->crash_report);
		}
		return NULL;
	} else if (r_str_startswith (command, "dl2")) {
		if (command[3] == ' ') {
			GError *error = NULL;
			gchar *path = r_str_trim_dup (command + 3);
			if (path) {
				gchar *entry = strchr (path, ' ');
				if (entry) {
					*entry++ = 0;
				} else {
					entry = "main";
				}
				frida_device_inject_library_file_sync (rf->device,
					rf->pid, path, entry, "", rf->cancellable, &error);
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
	} else if (!strcmp (command, "dc") && (rf->suspended || rf->suspended2)) {
		resume (rf);
		return NULL;
	}
	char *slurpedData = NULL;
	if (command[0] == '.') {
		switch (command[1]) {
		case '?':
			eprintf ("Usage: .[-] [filename]  # load and run the given script into the agent\n");
			eprintf (".              list loaded plugins via r2frida.pluginRegister()\n");
			eprintf (".:[file.js]    run cfg.editor and run the script in the agent\n");
			eprintf ("..foo.js       load and eternalize given script in the agent size\n");
			eprintf (".-foo          unload r2frida plugin via r2frida.pluginUnregister()\n");
			eprintf (". file.js      run this script in the agent side\n");
			break;
		case ':':
			{
				const char *arg = r_str_trim_head_ro (command + 2);
				// eprintf ("%s\n", arg);
				slurpedData = r_core_editor (rf->r2core, *arg? arg: NULL, NULL);
				if (slurpedData) {
					// eprintf ("%s\n", slurpedData);
					builder = build_request ("evaluate");
					json_builder_set_member_name (builder, "code");
					json_builder_add_string_value (builder, slurpedData);
				} else {
					return NULL;
				}
			}
			break;
		case '.':
			{
				const char *filename = r_str_trim_head_ro (command + 2);
				(void)__eternalizeScript (rf, filename);
			}
			return strdup ("");
		case ' ':
			{
				const char *filename = r_str_trim_head_ro (command + 2);
				builder = build_request ("evaluate");
				const bool is_c = r_str_endswith (filename, ".c");
				const bool is_ts = r_str_endswith (filename, ".ts");
				json_builder_set_member_name (builder, is_c? "ccode": "code");
				if (is_ts && r2f_compiler ()) {
#if __WINDOWS__
					R_LOG_ERROR ("Can't compile typescript on the fly with frida 15");
#else
					GError *error = NULL;
					FridaCompiler *compiler = frida_compiler_new (rf->device_manager);
					g_signal_connect (compiler, "diagnostics", G_CALLBACK (on_compiler_diagnostics), rf);
					slurpedData = frida_compiler_build_sync (compiler, filename, NULL, NULL, &error);
					g_object_unref (compiler);
#endif
				} else {
					slurpedData = r_file_slurp (filename, NULL);
				}
				if (!slurpedData) {
					R_LOG_ERROR ("Cannot slurp %s", filename);
					return NULL;
				}
				json_builder_add_string_value (builder, slurpedData);
			}
			break;
		case '-':
			builder = build_request ("evaluate");
			json_builder_set_member_name (builder, "code");
			slurpedData = r_str_newf ("r2frida.pluginUnregister('%s')", command + 2);
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
			builder = build_request ("evaluate");
			json_builder_set_member_name (builder, "code");
			char *code = r_str_newf ("Java.perform(function(){%s;})", command + 1);
			json_builder_add_string_value (builder, code);
			free (code);
		} else if (command[0] == ' ') {
			builder = build_request ("evaluate");
			json_builder_set_member_name (builder, "code");
			json_builder_add_string_value (builder, command + 1);
		} else {
			builder = build_request ("perform");
			json_builder_set_member_name (builder, "command");
			json_builder_add_string_value (builder, command);
		}
	}
	free (slurpedData);

	rf->inputmode = true;
	result = perform_request (rf, builder, NULL, NULL);
	if (!result) {
		return NULL;
	}
	{
		char *s = r_strbuf_drain (rf->sb);
		if (*s) {
			io->cb_printf ("%s\n", s);
		}
		free (s);
		rf->sb = r_strbuf_new ("");
	}
	rf->inputmode = false;

	if (!json_object_has_member (result, "value")) {
		return NULL;
	}
	const char *value = json_object_get_string_member (result, "value");
	char *sys_result = NULL;
	if (value && strcmp (value, "undefined")) {
		const bool is_fs_io = command[0] == 'm';
		if (is_fs_io) {
			sys_result = strdup (value);
		} else {
			io->cb_printf ("%s\n", value);
		}
	}
	json_object_unref (result);

	return sys_result;
}

static void load_scripts(RCore *core, RIODesc *fd, const char *path) {
	r_return_if_fail (core && fd && path);
	RList *files = r_sys_dir (path);
	RListIter *iter;
	const char *file;
	r_list_foreach (files, iter, file) {
		if (r_str_endswith (file, ".js")) {
			char *cmd = r_str_newf (". %s"R_SYS_DIR"%s", path, file);
			if (r2f_debug_uri ()) {
				R_LOG_INFO ("Loading %s", file);
			}
			char *s = __system_continuation (core->io, fd, cmd);
			free (cmd);
			if (s) {
				r_cons_printf ("%s\n", s);
				// eprintf ("%s\n", s);
				free (s);
			}
		}
	}
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	GError *error = NULL;

	R2FridaLaunchOptions *lo = r2frida_launchopt_new (pathname);
	if (!lo) {
		return NULL;
	}

	frida_init ();

	RIOFrida *rf = r_io_frida_new (io);
	if (!rf) {
		goto error;
	}
	rf->device_manager = frida_device_manager_new ();
	if (!__check (io, pathname, false)) {
		goto error;
	}

	bool rc = resolve_target (rf, pathname, lo, rf->cancellable);
	if (!rc) {
		goto error;
	}
	if (R_STR_ISEMPTY (lo->device_id)) {
		free (lo->device_id);
		lo->device_id = strdup ("local");
	}
	const char *devid = (R_STR_ISNOTEMPTY (lo->device_id))? lo->device_id: NULL;
	rc = resolve_device (rf, devid, &rf->device, rf->cancellable);
	if (rc && rf->device) {
		if (!lo->spawn && !resolve_process (rf->device, lo, rf->cancellable)) {
			goto error;
		}
	}
	if (R_STR_ISEMPTY (lo->process_specifier)) {
		if (dumpApplications (rf->device, rf->cancellable) == 0) {
			dumpProcesses (rf->device, rf->cancellable);
		}
	}
	R_LOG_DEBUG ("");
	if (r2f_debug_uri ()) {
		printf ("device: %s\n", r_str_get (lo->device_id));
		printf ("pname: %s\n", r_str_get (lo->process_specifier));
		printf ("pid: %d\n", lo->pid);
		printf ("spawn: %s\n", r_str_bool (lo->spawn));
		printf ("run: %s\n", r_str_bool (lo->run));
		printf ("pid_valid: %s\n", r_str_bool (lo->pid_valid));
		goto error;
	}
	if (!rc) {
		goto error;
	}
	if (!rf->device) {
		R_LOG_ERROR ("This should never happen");
		// rf->device = get_device_manager (rf->device_manager, "local", rf->cancellable, &error);
		goto error;
	}
	if (lo->spawn) {
		char *package_name = resolve_package_name_by_process_name (rf->device, rf->cancellable, lo->process_specifier);
		if (package_name) {
			free (lo->process_specifier);
			lo->process_specifier = package_name;
		}
		// try to resolve it as an app name too
		char *a = strdup (lo->process_specifier);
		char **argv = r_str_argv (a, NULL);
		if (!argv) {
			R_LOG_ERROR ("Invalid process specifier");
			goto error;
		}
		if (!*argv) {
			R_LOG_ERROR ("Invalid arguments for spawning");
			r_str_argv_free (argv);
			goto error;
		}
		const int argc = g_strv_length (argv);
		FridaSpawnOptions *options = frida_spawn_options_new ();
		if (argc > 1) {
			frida_spawn_options_set_argv (options, argv, argc);
		}
		// frida_spawn_options_set_stdio (options, FRIDA_STDIO_PIPE);
		rf->pid = frida_device_spawn_sync (rf->device, argv[0], options, rf->cancellable, &error);
		g_object_unref (options);
		r_str_argv_free (argv);
		free (a);

		if (error) {
			if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
				R_LOG_ERROR ("Cannot spawn: %s", error->message);
			}
			goto error;
		}
		rf->suspended = !lo->run;
	} else {
		rf->pid = lo->pid;
		rf->suspended = false;
	}
	if (!rf->device) {
		error = NULL;
		goto error;
	}
	rf->session = frida_device_attach_sync (rf->device, rf->pid, NULL, rf->cancellable, &error);
	if (error) {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			R_LOG_ERROR ("Cannot attach: %s", error->message);
		}
		goto error;
	}

	FridaScriptOptions * options = frida_script_options_new ();
	frida_script_options_set_name (options, "_agent");
	FridaScriptRuntime runtime = r2f_jsruntime ();
	frida_script_options_set_runtime (options, runtime);

	const char *code_buf = NULL;
	char *code_malloc_data = NULL;
	size_t code_size = 0;

	char *r2f_as = r_sys_getenv ("R2FRIDA_AGENT_SCRIPT");
	if (r2f_as) {
		code_malloc_data = r_file_slurp (r2f_as, &code_size);
		code_buf = code_malloc_data;
		if (!code_buf) {
			R_LOG_ERROR ("Cannot slurp R2FRIDA_AGENT_SCRIPT");
		}
		free (r2f_as);
	}

	if (code_buf == NULL) {
		code_size = sizeof (r_io_frida_agent_code);
		code_malloc_data = malloc (code_size + 1);
		if (!code_malloc_data) {
			R_LOG_ERROR ("Cannot allocate enough memory for the agent");
			goto error;
		}
		memcpy (code_malloc_data, r_io_frida_agent_code, code_size);
		code_malloc_data[code_size] = 0;
		code_buf = code_malloc_data;
	}

	rf->script = frida_session_create_script_sync (rf->session, code_buf, options, rf->cancellable, &error);

	free (code_malloc_data);

	if (error) {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			R_LOG_ERROR ("Cannot create script: %s", error->message);
		}
		goto error;
	}

	rf->onmsg_handler = g_signal_connect (rf->script, "message", G_CALLBACK (on_message), rf);
	rf->ondtc_handler = g_signal_connect (rf->session, "detached", G_CALLBACK (on_detached), rf);

	frida_script_load_sync (rf->script, rf->cancellable, &error);
	if (error) {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			R_LOG_ERROR ("Cannot load script: %s", error->message);
		}
		goto error;
	}

	// safe io is required at start time, otherwise frida-server
	// locks in Memory.readByteArray() which locks the second shell
	request_safe_io (rf, true);

	const char *autocompletions[] = {
		"!!!:chcon",
		"!!!:eval",
		"!!!:e",
		"!!!:e/",
		"!!!:env",
		"!!!:j",
		"!!!:i",
		"!!!:ii",
		"!!!:il",
		"!!!:is",
		"!!!:isa $flag",
		"!!!:iE",
		"!!!:iEa $flag",
		"!!!:ic",
		"!!!:ip",
		"!!!:init",
		"!!!:fd $flag",
		"!!!:dd",
		"!!!:ddj",
		"!!!:?",
		"!!!:?V",
		"!!!:/",
		"!!!:/i",
		"!!!:/ij",
		"!!!:/w",
		"!!!:/wj",
		"!!!:/x",
		"!!!:/xj",
		"!!!:/v1 $flag",
		"!!!:/v2 $flag",
		"!!!:/v4 $flag",
		"!!!:/v8 $flag",
		"!!!:dt $flag",
		"!!!:dt- $flag",
		"!!!:dt-*",
		"!!!:dth",
		"!!!:dtq",
		"!!!:dtr",
		"!!!:dtS",
		"!!!:dtSf $flag",
		"!!!:dc",
		"!!!:di",
		"!!!:dii",
		"!!!:dibt",
		"!!!:dibf",
		"!!!:di0",
		"!!!:di1",
		"!!!:di-1",
		"!!!:dl",
		"!!!:dl2",
		"!!!:dx",
		"!!!:dm",
		"!!!:dma",
		"!!!:dma-",
		"!!!:dmas",
		"!!!:dmaw",
		"!!!:dmad",
		"!!!:dmal",
		"!!!:dmm",
		"!!!:dmh",
		"!!!:dmhm",
		"!!!:dmp $flag",
		"!!!:db",
		"!!!:dp",
		"!!!:dpj",
		"!!!:dpt",
		"!!!:dr",
		"!!!:drj",
		"!!!:dk",
		"!!!:dkr",
		"!!!:t",
		"!!!:. $file",
		NULL
	};
	int i;
	for (i = 0; autocompletions[i]; i++) {
		COREBIND (io).cmd (rf->r2core, autocompletions[i]);
	}
	RIODesc *fd = r_io_desc_new (io, &r_io_plugin_frida, pathname, R_PERM_RWX, mode, rf);
	if (lo->run) {
		resume (rf);
	}
	r2frida_launchopt_free (lo);

	/* load scripts */
	RCore *core = rf->r2core;
	load_scripts (core, fd, R2_DATDIR "/r2frida/scripts");

#if R2_VERSION_NUMBER < 50709
	char *homepath = r_str_home (R_JOIN_4_PATHS (".local", "share", "r2frida", "scripts"));
#else
	char *homepath = r_xdg_datadir ("r2frida/scripts");
#endif
	load_scripts (core, fd, homepath);
	free (homepath);
	if (!user_wants_safe_io (rf->device)) {
		request_safe_io (rf, false);
	} else {
		R_LOG_INFO ("Using safe io mode.");
	}

	return fd;

error:
	g_clear_error (&error);
	r2frida_launchopt_free (lo);
	r_io_frida_free (rf);

	return NULL;
}

static FridaDevice *get_device_manager(FridaDeviceManager *manager, const char *type, GCancellable *cancellable, GError **error) {
#define D(x) if (debug) { printf ("%s\n", x); }
	const bool debug = r2f_debug_uri ();
	FridaDevice *device = NULL;
	if (R_STR_ISEMPTY (type)) {
		type = "local";
	}
	if (r_str_startswith (type, "usb")) {
		D ("get-usb-device");
		device = frida_device_manager_get_device_by_type_sync (manager, FRIDA_DEVICE_TYPE_USB, 0, cancellable, error);
	} else if (!strcmp (type, "local")) {
		D ("local-device");
		device = frida_device_manager_get_device_by_type_sync (manager, FRIDA_DEVICE_TYPE_LOCAL, 0, cancellable, error);
	} else if (strchr (type, ':')) { // host:port
		D ("get-usb-device");
		device = frida_device_manager_add_remote_device_sync (manager, type, NULL, cancellable, error);
	} else {
		if (debug) printf ("device(%s)", type);
		device = frida_device_manager_get_device_by_id_sync (manager, type, 0, cancellable, error);
	}
	return device;
}

static char *__system(RIO *io, RIODesc *fd, const char *command) {
	r_return_val_if_fail (io && fd && command, NULL);
	return __system_continuation (io, fd, command);
}

#if 0
static bool is_process_action(const char *rest) {
	if (!strcmp (rest, "attach")) {
		return true;
	}
	if (!strcmp (rest, "spawn")) {
		return true;
	}
	if (!strcmp (rest, "launch")) {
		return true;
	}
	return false;
}
#endif

/// uri parser ///

typedef enum {
	R2F_LINK_UNKNOWN = -1,
	R2F_LINK_LOCAL = 0,
	R2F_LINK_USB,
	R2F_LINK_REMOTE,
} R2FridaLink;

typedef enum {
	R2F_ACTION_UNKNOWN = -1,
	R2F_ACTION_ATTACH = 0,
	R2F_ACTION_SPAWN,
	R2F_ACTION_LAUNCH,
	R2F_ACTION_LIST_PIDS,
	R2F_ACTION_LIST_APPS,
} R2FridaAction;

static R2FridaAction parse_action(const char *a) {
	if (!strcmp (a, "attach")) {
		return R2F_ACTION_ATTACH;
	}
	if (!strcmp (a, "spawn")) {
		return R2F_ACTION_SPAWN;
	}
	if (!strcmp (a, "launch")) {
		return R2F_ACTION_LAUNCH;
	}
	if (!strcmp (a, "list")) {
		return R2F_ACTION_LIST_PIDS;
	}
	if (!strcmp (a, "apps")) {
		return R2F_ACTION_LIST_APPS;
	}
	return R2F_ACTION_UNKNOWN;
}

static R2FridaLink parse_link(const char *a) {
	if (!strcmp (a, "remote")) {
		return R2F_LINK_REMOTE;
	}
	if (!strcmp (a, "usb")) {
		return R2F_LINK_USB;
	}
	return R2F_LINK_LOCAL;
	// return R2F_LINK_UNKNOWN;
}

static bool resolve1(RIOFrida *rf, RList *args, R2FridaLaunchOptions *lo, GCancellable *cancellable) {
	const char *arg0 = r_list_get_n (args, 0);
	if (isdigit (*arg0)) {
		// frida://123 -- attach by process-id
		lo->pid = atopid (arg0, &lo->pid_valid);
		lo->spawn = false;
		lo->process_specifier = g_strdup (arg0);
	} else {
		// frida://vim -- attach by process-name
		lo->pid = -1;
		char *abspath = r_file_path (arg0);
		lo->spawn = (abspath && *abspath == '/');
		lo->process_specifier = abspath? abspath: g_strdup (arg0);
	}
	return true;
}

static bool resolve2(RIOFrida *rf, RList *args, R2FridaLaunchOptions *lo, GCancellable *cancellable) {
	const char *arg0 = r_list_get_n (args, 0);
	const char *arg1 = r_list_get_n (args, 1);
	R2FridaAction action = parse_action (arg0);
	switch (action) {
	case R2F_ACTION_LIST_APPS:
		{
		GError *error = NULL;
		const char *devid = (R_STR_ISEMPTY (arg1))? NULL: arg1;
		FridaDevice *device = get_device_manager (rf->device_manager, devid, cancellable, &error); // frida_device_manager_get_device_by_type_sync (device_manager, devid, 0, cancellable, &error);
		dumpApplications (device, cancellable);
		g_object_unref (device);
		}
		return false;
	case R2F_ACTION_LIST_PIDS:
		// frida://list/usb
		dumpDevices (rf, cancellable);
		return false;
	case R2F_ACTION_ATTACH:
		if (R_STR_ISEMPTY (arg1)) {
			return false;
		}
		lo->spawn = false;
		lo->pid = atopid (arg1, &lo->pid_valid);
		lo->process_specifier = g_strdup (arg1);
		return true;
	case R2F_ACTION_LAUNCH:
		lo->spawn = true;
		lo->run = true;
		lo->pid = -1;
		if (R_STR_ISEMPTY (arg1)) {
			return false;
		} else {
			char *abspath = r_file_path (arg1);
			lo->spawn = (abspath && *abspath == '/');
			lo->process_specifier = abspath? abspath: g_strdup (arg1);
		}
		return true;
	case R2F_ACTION_SPAWN:
		lo->spawn = true;
		lo->run = false;
		lo->pid = -1;
		if (R_STR_ISEMPTY (arg1)) {
			return false;
		} else {
			char *abspath = r_file_path (arg1);
			lo->spawn = (abspath && *abspath == '/');
			lo->process_specifier = abspath? abspath: g_strdup (arg1);
		}
		return true;
	case R2F_ACTION_UNKNOWN:
		break;
	}
	return false;
}

static bool resolve3(RIOFrida *rf, RList *args, R2FridaLaunchOptions *lo, GCancellable *cancellable) {
	const char *arg0 = r_list_get_n (args, 0);
	const char *arg1 = r_list_get_n (args, 1);
	const char *arg2 = r_list_get_n (args, 2);
	// frida://attach/usb//
	R2FridaAction action = parse_action (arg0);
	R2FridaLink link = parse_link (arg1);
	R_LOG_DEBUG ("action %d link %d\n", action, link);
	if (!*arg2) {
		// frida://attach/usb/
		dumpDevices (rf, cancellable);
	}
	return false;
}

static bool resolve4(RIOFrida *rf, RList *args, R2FridaLaunchOptions *lo, GCancellable *cancellable) {
	const char *arg0 = r_list_get_n (args, 0);
	const char *arg1 = r_list_get_n (args, 1);
	const char *arg2 = r_list_get_n (args, 2);
	const char *arg3 = r_list_get_n (args, 3);
	R2FridaAction action = parse_action (arg0);
	R2FridaLink link = parse_link (arg1);

	GError *error = NULL;
	const char *devid = R_STR_ISNOTEMPTY (arg2)? arg2: NULL;
	switch (link) {
	case R2F_LINK_USB:
		devid = R_STR_ISNOTEMPTY (arg2)? arg2: "usb";
		break;
	case R2F_LINK_REMOTE:
		devid = arg2;
		break;
	default:
		devid = NULL;
		break;
	}
	FridaDevice *device = get_device_manager (rf->device_manager, devid, cancellable, &error);

	// frida://attach/usb//
	switch (action) {
	case R2F_ACTION_UNKNOWN:
		break;
	case R2F_ACTION_LIST_APPS:
		if (device) {
			if (!dumpApplications (device, cancellable)) {
				R_LOG_ERROR ("Cannot enumerate apps");
			}
		} else {
			R_LOG_ERROR ("Cannot find peer");
		}
		break;
	case R2F_ACTION_LIST_PIDS:
		if (device) {
			dumpProcesses (device, cancellable);
		} else {
			R_LOG_ERROR ("Cannot find peer");
		}
		break;
	case R2F_ACTION_LAUNCH:
	case R2F_ACTION_SPAWN:
	case R2F_ACTION_ATTACH:
		if (!*arg3) {
			if (device) {
				if (action == R2F_ACTION_SPAWN || action == R2F_ACTION_LAUNCH) {
					if (!dumpApplications (device, cancellable)) {
						R_LOG_ERROR ("Cannot enumerate apps");
					}
				} else {
					dumpProcesses (device, cancellable);
				}
			}
		} else {
			lo->spawn = (action == R2F_ACTION_SPAWN || action == R2F_ACTION_LAUNCH);
			lo->run = action == R2F_ACTION_LAUNCH;
			lo->pid = -1;
			if (link == R2F_LINK_USB) {
				lo->device_id = strdup (devid);
			} else {
				lo->device_id = strdup (arg2);
			}
			lo->process_specifier = strdup (arg3);
			return true;
		}
		break;
#if 0
		// automatically resolve the deviceid
		char *first_word = g_strndup (first_field, second_field - first_field - 1);

		if (resolve_device_id_as_uriroot (first_word, second_field, lo, cancellable)) {
			g_free (first_word);
			return true;
		}
		lo->device_id = first_word;
#endif
	}
	return false;
}

static bool resolve_target(RIOFrida *rf, const char *pathname, R2FridaLaunchOptions *lo, GCancellable *cancellable) {
	const char *first_field = pathname + 8;
	// local, usb, remote
	// attach, spawn, launch, list
	if (!strcmp (first_field, "?")) {
		eprintf ("%s\n", helpmsg);
		return false;
	}
	lo->run = false;
	lo->spawn = false;

	const size_t uri_len = strlen ("frida://");
	if (strncmp (pathname, "frida://", uri_len)) {
		return false;
	}
	if (!pathname[uri_len]) {
		GError *error = NULL;
		FridaDevice *device = get_device_manager (rf->device_manager, "local", cancellable, &error);
		if (device) {
			dumpProcesses (device, cancellable);
			g_object_unref (device);
		} else {
			R_LOG_ERROR ("Cannot find device.\n");
		}
		return false;
	}
	char *a = strdup (pathname + uri_len);
	if (*a == '/' || !strncmp (a, "./", 2)) {
		// frida:///path/to/file
		lo->spawn = true;
		lo->process_specifier = a;
		return true;
	}

	RList *args = r_str_split_list (a, "/", 4);
	size_t args_len = r_list_length (args);

	bool res = false;
	switch (args_len) {
	case 1: res = resolve1 (rf, args, lo, cancellable); break;
	case 2: res = resolve2 (rf, args, lo, cancellable); break;
	case 3: res = resolve3 (rf, args, lo, cancellable); break;
	case 4: res = resolve4 (rf, args, lo, cancellable); break;
	default:
		R_LOG_ERROR ("Invalid URI");
		break;
	}

	r_list_free (args);
	free (a);
	return res;
}

static bool resolve_device(RIOFrida *rf, const char *device_id, FridaDevice **device, GCancellable *cancellable) {
	FridaDeviceManager *manager = rf->device_manager;
	GError *error = NULL;

	*device = get_device_manager (manager, device_id, cancellable, &error);
	if (error) {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			R_LOG_ERROR ("%s", error->message);
		}
		g_error_free (error);
		return false;
	}

	return true;
}

static bool resolve_process(FridaDevice *device, R2FridaLaunchOptions *lo, GCancellable *cancellable) {
	r_return_val_if_fail (device && lo, false);
	GError *error = NULL;

	if (lo->pid_valid) {
		return true;
	}
	if (lo->process_specifier) {
		if (*lo->process_specifier) {
			int number = atopid (lo->process_specifier, &lo->pid_valid);
			if (lo->pid_valid) {
				lo->pid = number;
				return true;
			}
		} else {
			dumpProcesses (device, cancellable);
		}
	}
	if (r2f_debug_uri ()) {
		return true;
	}

	if (!lo->process_specifier) {
		return false;
	}
	FridaProcess *process = frida_device_get_process_by_name_sync (
		device, lo->process_specifier, 0, cancellable, &error);
	if (error != NULL) {
		error = NULL;
		char *procname = resolve_process_name_by_package_name(device, cancellable, lo->process_specifier);
		if (procname) {
			free (lo->process_specifier);
			lo->process_specifier = procname;
		}
		process = frida_device_get_process_by_name_sync (
		device, lo->process_specifier, 0, cancellable, &error);
	}
	if (error != NULL) {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			R_LOG_ERROR ("%s", error->message);
		}
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

static void add_offset_parameter(JsonBuilder *builder, ut64 off) {
	char offstr[2 + 16 + 1];
	json_builder_set_member_name (builder, "offset");
	snprintf (offstr, sizeof (offstr), "0x%"PFMT64x, off);
	json_builder_add_string_value (builder, offstr);
}

static JsonObject *perform_request(RIOFrida *rf, JsonBuilder *builder, GBytes *data, GBytes **bytes) {
	JsonObject *reply_stanza = NULL;
	GBytes *reply_bytes = NULL;

	json_builder_end_object (builder);
	json_builder_end_object (builder);
	JsonNode *root = json_builder_get_root (builder);
	char *message = json_to_string (root, FALSE);
	json_node_unref (root);
	g_object_unref (builder);

	R_LOG_DEBUG ("perform_request (%s)", message);
	frida_script_post (rf->script, message, data);

	g_free (message);
	g_bytes_unref (data);

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
		case FRIDA_SESSION_DETACH_REASON_PROCESS_REPLACED:
			R_LOG_INFO ("Process replaced");
			break;
		case FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED:
			R_LOG_INFO ("Target process terminated");
			break;
		case FRIDA_SESSION_DETACH_REASON_CONNECTION_TERMINATED:
			R_LOG_INFO ("Server terminated");
			break;
		case FRIDA_SESSION_DETACH_REASON_DEVICE_LOST:
			R_LOG_INFO ("Device lost");
			break;
		}
		return NULL;
	}

	if (json_object_has_member (reply_stanza, "error")) {
		R_LOG_ERROR ("error: %s", json_object_get_string_member (reply_stanza, "error"));
		json_object_unref (reply_stanza);
		g_bytes_unref (reply_bytes);
		return NULL;
	}

	if (bytes) {
		*bytes = reply_bytes;
	} else {
		g_bytes_unref (reply_bytes);
	}

	R_LOG_DEBUG ("request performed");
	return reply_stanza;
}

static void exec_pending_cmd_if_needed(RIOFrida * rf) {
	if (!rf->pending_cmd) {
		return;
	}
	char *output = COREBIND (rf->io).cmdstr (rf->r2core, rf->pending_cmd->cmd_string);

	ut64 serial = rf->pending_cmd->serial;
	pending_cmd_free (rf->pending_cmd);
	rf->pending_cmd = NULL;

	if (output) {
		JsonBuilder * builder = build_request ("cmd");
		if (builder) {
			json_builder_set_member_name (builder, "output");
			json_builder_add_string_value (builder, output);
			json_builder_set_member_name (builder, "serial");
			json_builder_add_int_value (builder, serial);

			perform_request_unlocked (rf, builder, NULL, NULL);
		}
		R_FREE (output);
	}
}

static void perform_request_unlocked(RIOFrida *rf, JsonBuilder *builder, GBytes *data, GBytes **bytes) {
	json_builder_end_object (builder);
	json_builder_end_object (builder);
	JsonNode *root = json_builder_get_root (builder);
	char *message = json_to_string (root, FALSE);
	json_node_unref (root);
	g_object_unref (builder);

	frida_script_post (rf->script, message, data);

	g_free (message);
	g_bytes_unref (data);
}

static void on_stanza(RIOFrida *rf, JsonObject *stanza, GBytes *bytes) {
	g_mutex_lock (&rf->lock);
	rf->received_reply = true;
	rf->reply_stanza = stanza;
	rf->reply_bytes = bytes? g_bytes_ref (bytes): NULL;
	if (!rf->reply_stanza && !rf->reply_bytes) {
		// some messages don't require an ack. let's just move on
		R_LOG_DEBUG ("rf->reply_{stanza(%p) & bytes(%p)} are null",
				rf->reply_stanza, rf->reply_bytes);
	}
	g_cond_signal (&rf->cond);
	g_mutex_unlock (&rf->lock);
}

static void on_detached(FridaSession *session, FridaSessionDetachReason reason, FridaCrash *crash, gpointer user_data) {
	RIOFrida *rf = user_data;
	if (!rf || !rf->io) {
		return;
	}
	g_mutex_lock (&rf->lock);
	rf->detached = true;
	rf->detach_reason = reason;
	R_LOG_INFO ("DetachReason: %s", detachReasonAsString (rf));
	if (crash) {
		const char *crash_report = frida_crash_get_report (crash);
		free (rf->crash_report);
		rf->crash_report = strdup (crash_report);
		R_LOG_INFO ("CrashReport: %s", crash_report);
	}
	rf->crash = (crash != NULL) ? g_object_ref (crash) : NULL;
	g_cond_signal (&rf->cond);
	g_mutex_unlock (&rf->lock);
}

static void on_breakpoint_event(RIOFrida *rf, JsonObject *cmd_stanza) {
	g_mutex_lock (&rf->lock);
	g_assert (!rf->pending_cmd);
	if (json_object_has_member (cmd_stanza, "cmd")) {
		const char *command = json_object_get_string_member (cmd_stanza, "cmd");
		if (R_STR_ISNOTEMPTY (command)) {
			r_core_cmd0 (rf->r2core, command);
			r_cons_flush ();
		}
	}
	rf->suspended2 = true;
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

static void on_message_send(RIOFrida *rf, FridaScript *script, JsonObject *root, const char *raw_message, GBytes *data) {
	JsonNode *payload_node = json_object_get_member (root, "payload");
	JsonNodeType type = json_node_get_node_type (payload_node);
	if (type == JSON_NODE_OBJECT) {
		JsonObject *payload = json_object_ref (json_object_get_object_member (root, "payload"));
		if (payload && json_object_has_member (payload, "stanza")) {
			JsonObject *stanza = json_object_get_object_member (payload, "stanza");
			const char *name = json_object_get_string_member (payload, "name");

			if (name && !strcmp (name, "reply")) {
				if (stanza) {
					JsonNode *stanza_node = json_object_get_member (payload, "stanza");
					JsonNodeType stanza_type = json_node_get_node_type (stanza_node);
					if (stanza_type == JSON_NODE_OBJECT) {
						on_stanza (rf, json_object_ref (json_object_get_object_member (payload, "stanza")), data);
					} else {
						R_LOG_ERROR ("Bug in the agent, cannot find stanza in the message: %s", raw_message);
					}
				} else {
					R_LOG_ERROR ("Bug in the agent, expected an object: %s", raw_message);
				}
			} else if (name && !strcmp (name, "breakpoint-event")) {
				on_breakpoint_event (rf, json_object_get_object_member (payload, "stanza"));
			} else if (name && !strcmp (name, "cmd")) {
				on_cmd (rf, json_object_get_object_member (payload, "stanza"));
			} else if (name && !strcmp (name, "log")) {
				JsonNode *stanza_node = json_object_get_member (payload, "stanza");
				if (stanza && stanza_node) {
					JsonNode *message_node = json_object_get_member (stanza, "message");
					if (message_node) {
						JsonNodeType type = json_node_get_node_type (message_node);
						char *message = NULL;
						if (type == JSON_NODE_OBJECT) {
							message = json_to_string (message_node, FALSE);
						} else {
							const char *cmessage = json_object_get_string_member (stanza, "message");
							if (cmessage) {
								message = strdup (cmessage);
							}
						}
						if (message) {
							eprintf ("%s\n", message);
							free (message);
						}
					}
				} else {
					R_LOG_WARN ("Missing stanza for log message");
				}
			} else if (name && !strcmp (name, "log-file")) {
				JsonNode *stanza_node = json_object_get_member (payload, "stanza");
				if (stanza && stanza_node) {
					const char *filename = json_object_get_string_member (stanza, "filename");
					JsonNode *message_node = json_object_get_member (stanza, "message");
					if (message_node) {
						JsonNodeType type = json_node_get_node_type (message_node);
						char *message = (type == JSON_NODE_OBJECT)
							? json_to_string (message_node, FALSE)
							: strdup (json_object_get_string_member (stanza, "message"));
						if (filename && message) {
							bool sent = false;
							message = r_str_append (message, "\n");
							if (*filename == '|') {
								// redirect the message to a program shell
								char *emsg = r_str_escape (message);
								r_sys_cmdf ("%s \"%s\"", r_str_trim_head_ro (filename + 1), emsg);
								free (emsg);
							} else if (r_str_startswith (filename, "tcp:")) {
								char *host = strdup (filename + 4);
								char *port = strchr (host, ':');
								if (port) {
									*port++ = 0;
									if (!r_socket_is_connected (rf->s)) {
										(void)r_socket_connect (rf->s, host, port, R_SOCKET_PROTO_TCP, 0);
									}
									if (r_socket_is_connected (rf->s)) {
										size_t msglen = strlen (message);
										if (r_socket_write (rf->s, message, msglen) == msglen) {
											sent = true;
										}
									}
								}
							}
							if (!sent) {
								(void) r_file_dump (filename, (const ut8*)message, -1, true);
							}
						}
						free (message);
					} else {
						R_LOG_WARN ("Missing message node");
					}
					// json_node_unref (stanza_node);
				} else {
					R_LOG_WARN ("Missing stanza for log-file message");
				}
			} else {
				if (!r_str_startswith (name, "action-")) {
					R_LOG_WARN ("Unknown packet named '%s'", name);
				}
			}
			json_object_unref (payload);
		} else {
			R_LOG_ERROR ("Unexpected payload (%s)", raw_message);
		}
	} else {
		R_LOG_ERROR ("Bug in the agent, expected an object: %s", raw_message);
	}
}

static void on_message(FridaScript *script, const char *raw_message, GBytes *data, gpointer user_data) {
	RIOFrida *rf = user_data;
	JsonNode *message = json_from_string (raw_message, NULL);
	g_assert (message != NULL);
	JsonObject *root = json_node_get_object (message);
	const char *type = json_object_get_string_member (root, "type");
	if (!type) {
		return;
	}

	if (!strcmp (type, "send")) {
		on_message_send (rf, script, root, raw_message, data);
	} else if (!strcmp (type, "log")) {
		// This is reached from the agent when calling console.log
		JsonNode *payload_node = json_object_get_member (root, "payload");
		// JsonNodeType type = json_node_get_node_type (payload_node);
		const char *message = json_node_get_string (payload_node);
		if (message) {
			const char cmd_prefix[] = "[r2cmd]";
			if (r_str_startswith (message, cmd_prefix)) {
				const char *cmd = message + strlen (cmd_prefix);
				// eprintf ("Running r2 command: '%s'\n", cmd);
#if ((R2_VERSION_MAJOR == 5 && R2_VERSION_MINOR >= 4) || R2_VERSION_MAJOR > 5)
				r_core_cmd_queue (rf->r2core, cmd);
#else
				r_core_cmd0 (rf->r2core, cmd);
#endif
			} else {
				// eprintf ("LOG MESSAGE RECEIVED (%s)\n", message);
				if (rf->inputmode) {
					r_strbuf_append (rf->sb, message);
				} else {
					eprintf ("%s\n", message);
				}
			}
		} else {
			R_LOG_ERROR ("Missing message: %s", message);
		}
	} else {
		R_LOG_ERROR ("Unhandled message: %s", raw_message);
	}

	json_node_unref (message);
}

static void dumpDevices(RIOFrida *rf, GCancellable *cancellable) {
	if (r2f_debug_uri ()) {
		printf ("dump-devices\n");
		return;
	}
	gint i;
	GError *error = NULL;
	FridaDeviceList *list = frida_device_manager_enumerate_devices_sync (rf->device_manager, cancellable, &error);
	if (error) {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			R_LOG_ERROR ("%s", error->message);
		}
		goto beach;
	}
	gint num_devices = frida_device_list_size (list);

	GArray *devices = g_array_sized_new (FALSE, FALSE, sizeof (FridaDevice *), num_devices);
	for (i = 0; i != num_devices; i++) {
		FridaDevice *device = frida_device_list_get (list, i);
		g_array_append_val (devices, device);
		g_object_unref (device); /* borrow it */
	}
	g_array_sort (devices, compareDevices);

	print_list (DEVICES, devices, num_devices);
beach:
	g_clear_error (&error);
	g_clear_object (&list);
}

static char *resolve_package_name_by_process_name(FridaDevice *device, GCancellable *cancellable, const char *process_name) {
	char *res = NULL;
	gint num_applications = 0;

	if (r2f_debug_uri ()) {
		printf ("resolve_package_name_by_process_name\n");
		return NULL;
	}

	GError *error = NULL;
	FridaApplicationList *list = frida_device_enumerate_applications_sync (device, NULL, cancellable, &error);
	if (error != NULL) {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			R_LOG_ERROR ("%s", error->message);
		}
		goto beach;
	}
	num_applications = frida_application_list_size (list);

	GArray *applications = g_array_sized_new (FALSE, FALSE, sizeof (FridaApplication *), num_applications);
	if (applications) {
		gint i;
		for (i = 0; i < num_applications; i++) {
			FridaApplication *application = frida_application_list_get (list, i);
			if (application) {
				const char *name = frida_application_get_name (application);
				if (!strcmp (process_name, name)) {
					res = strdup (frida_application_get_identifier (application));
					break;
				}
				g_object_unref (application); /* borrow it */
			}
		}
		g_array_free (applications, num_applications);
	}

beach:
	g_clear_error (&error);
	g_clear_object (&list);
	return res;
}

static char *resolve_process_name_by_package_name(FridaDevice *device, GCancellable *cancellable, const char *bundleid) {
	char *res = NULL;
	gint i;

	if (r2f_debug_uri ()) {
		printf ("resolve_process_name_by_package_name\n");
		return NULL;
	}

	GError *error = NULL;
	FridaApplicationList *list = frida_device_enumerate_applications_sync (device, NULL, cancellable, &error);
	if (error != NULL) {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			R_LOG_ERROR ("%s", error->message);
		}
		goto beach;
	}
	gint num_applications = frida_application_list_size (list);

	GArray *applications = g_array_sized_new (FALSE, FALSE, sizeof (FridaApplication *), num_applications);
	if (applications) {
		for (i = 0; i != num_applications; i++) {
			FridaApplication *application = frida_application_list_get (list, i);
			if (application) {
				const char *bid = frida_application_get_identifier (application);
				if (!strcmp (bundleid, bid)) {
					res = strdup (frida_application_get_name (application));
					break;
				}
				g_object_unref (application); /* borrow it */
			}
		}
		g_array_free (applications, num_applications);
	}

beach:
	g_clear_error (&error);
	g_clear_object (&list);
	return res;
}

static int dumpApplications(FridaDevice *device, GCancellable *cancellable) {
	FridaApplicationList *list;
	GArray *applications;
	gint i, num_applications = 0;
	GError *error = NULL;

	if (r2f_debug_uri ()) {
		printf ("dump-apps\n");
		return 0;
	}

	list = frida_device_enumerate_applications_sync (device, NULL, cancellable, &error);
	if (error != NULL) {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			R_LOG_ERROR ("%s", error->message);
		}
		goto beach;
	}
	num_applications = frida_application_list_size (list);

	applications = g_array_sized_new (FALSE, FALSE, sizeof (FridaApplication *), num_applications);
	for (i = 0; i != num_applications; i++) {
		FridaApplication *application = frida_application_list_get (list, i);
		g_array_append_val (applications, application);
		g_object_unref (application); /* borrow it */
	}
	g_array_sort (applications, compareProcesses);

	print_list (APPLICATIONS, applications, num_applications);
beach:
	g_clear_error (&error);
	g_clear_object (&list);

	return num_applications;
}

static void dumpProcesses(FridaDevice *device, GCancellable *cancellable) {
	if (!device) {
		R_LOG_ERROR ("no device selected");
		return;
	}
	if (r2f_debug_uri ()) {
		printf ("dump-procs\n");
		return;
	}
	gint i;
	GError *error = NULL;

	FridaProcessList *list = frida_device_enumerate_processes_sync (device, NULL, cancellable, &error);
	if (error) {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			R_LOG_ERROR ("%s", error->message);
		}
		goto beach;
	}
	gint num_processes = frida_process_list_size (list);

	GArray *processes = g_array_sized_new (FALSE, FALSE, sizeof (FridaProcess *), num_processes);
	for (i = 0; i != num_processes; i++) {
		FridaProcess *process = frida_process_list_get (list, i);
		g_array_append_val (processes, process);
		g_object_unref (process); /* borrow it */
	}
	g_array_sort (processes, compareProcesses);

	print_list (PROCESSES, processes, num_processes);
beach:
	g_clear_error (&error);
	g_clear_object (&list);
}

static gint compareDevices(gconstpointer element_a, gconstpointer element_b) {
	FridaDevice *a = *(FridaDevice **) element_a;
	FridaDevice *b = *(FridaDevice **) element_b;

	gint score_a = computeDeviceScore (a);
	gint score_b = computeDeviceScore (b);
	if (score_a != score_b) {
		return score_b - score_a;
	}
	return strcmp (frida_device_get_name (a), frida_device_get_name (b));
}

static gint compareProcesses(gconstpointer element_a, gconstpointer element_b) {
	FridaProcess *a = *(FridaProcess **) element_a;
	FridaProcess *b = *(FridaProcess **) element_b;

	gint name_equality = strcmp (frida_process_get_name (a), frida_process_get_name (b));
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
	return 0;
}

static int atopid(const char *maybe_pid, bool *valid) {
	char *endptr;
	int number = strtol (maybe_pid, &endptr, 10);
	*valid = endptr == NULL || (endptr - maybe_pid) == strlen (maybe_pid);
	return number;
}

static void print_list(R2FridaListType type, GArray *items, gint num_items) {
	guint i;
	GEnumClass *type_enum;

	RTable *table = r_table_new ("print_list");

	switch (type) {
	case APPLICATIONS:
		r_table_set_columnsf (table, "dss", "PID", "Name", "Identifier");
		for (i = 0; i < num_items; i++) {
			FridaApplication *application = g_array_index (items, FridaApplication*, i);
			guint pid = frida_application_get_pid (application);
			char *arg = pid? r_str_newf ("%d", pid): strdup ("-");
			r_table_add_rowf (table, "sss",
				arg,
				frida_application_get_name (application),
				frida_application_get_identifier (application)
			);
		}
		break;
	case PROCESSES:
		r_table_set_columnsf (table, "ds", "PID", "Name");
		for (i = 0; i < num_items; i++) {
			FridaProcess *process = g_array_index (items, FridaProcess *, i);
			r_table_add_rowf (table, "ds",
				frida_process_get_pid (process),
				frida_process_get_name (process)
			);
		}
		break;
	case DEVICES:
		r_table_set_columnsf (table, "sss", "Id", "Type", "Name");
		type_enum = g_type_class_ref (FRIDA_TYPE_DEVICE_TYPE);
		for (i = 0; i < num_items; i++) {
			FridaDevice *device;
			GEnumValue *type;
			device = g_array_index (items, FridaDevice *, i);
			type = g_enum_get_value (type_enum, frida_device_get_dtype (device));
			r_table_add_rowf (table, "sss",
				frida_device_get_id (device),
				type->value_nick,
				frida_device_get_name (device)
			);
		}
		g_type_class_unref (type_enum);
		break;
	default:
		goto error;
	}
	r_table_align (table, 0, R_TABLE_ALIGN_LEFT);
	r_table_align (table, 1, R_TABLE_ALIGN_RIGHT);
	r_table_align (table, 2, R_TABLE_ALIGN_RIGHT);
	r_table_sort (table, 0, 0);
	char *s = r_table_tostring (table);
	if (s) {
		r_cons_printf ("%s\n", s);
		free (s);
	}
error:
	r_table_free (table);
}

RIOPlugin r_io_plugin_frida = {
#if R2_VERSION_NUMBER >= 50809
	.meta = {
		.name = "frida",
		.desc = "io plugin for Frida " FRIDA_VERSION_STRING,
		.license = "MIT",
	},
#else
	.name = "frida",
	.desc = "io plugin for Frida " FRIDA_VERSION_STRING,
	.license = "MIT",
#endif
	.uris = "frida://",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __check,
#if ((R2_VERSION_MAJOR == 5 && R2_VERSION_MINOR >= 4) || R2_VERSION_MAJOR > 5)
	.seek = __lseek,
#else
	.lseek = __lseek,
#endif
	.write = __write,
	.resize = __resize,
	.system = __system,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_frida,
	.version = R2_VERSION,
#if ((R2_VERSION_MAJOR == 4 && R2_VERSION_MINOR >= 2) || R2_VERSION_MAJOR > 4)
	.pkgname = "r2frida"
#endif
};
#endif
