/* radare2 - MIT - Copyright 2016-2017 - pancake, oleavr */

#include <r_io.h>
#include <r_lib.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#ifndef WITH_CYCRIPT
#define WITH_CYCRIPT 1
#endif
#if WITH_CYCRIPT
#include "cylang.h"
#endif
#include "frida-core.h"

typedef struct {
	FridaDeviceManager *manager;
	FridaDevice *device;
	FridaSession *session;
	FridaScript *script;

	guint pid;
	GMutex lock;
	GCond cond;
	volatile bool detached;
	volatile FridaSessionDetachReason detach_reason;
	volatile bool received_reply;
	JsonObject *reply_stanza;
	GBytes *reply_bytes;
} RIOFrida;

#define RIOFRIDA_DEV(x) (((RIOFrida*)x->data)->device)
#define RIOFRIDA_SESSION(x) (((RIOFrida*)x->data)->session)

static bool parse_target(const char *pathname, char **device_id, char **process_specifier);
static bool resolve_device(FridaDeviceManager *manager, const char *device_id, FridaDevice **device);
static bool resolve_process(FridaDevice *device, const char *process_specifier, guint *pid);
static JsonBuilder *build_request(const char *type);
static JsonObject *perform_request(RIOFrida *rf, JsonBuilder *builder, GBytes *data, GBytes **bytes);
static void on_message(FridaScript *script, const char *message, GBytes *data, gpointer user_data);

extern RIOPlugin r_io_plugin_frida;

static const char *r_io_frida_agent_code =
#include "_agent.h"
;

static char *slurpFile(const char *str, int *usz) {
        size_t rsz;
        char *ret;
        FILE *fd;
        long sz;
        fd = r_sandbox_fopen (str, "rb");
	if (!fd) {
		if (*str == '/') {
			return NULL;
		}
		char *newfile = r_str_home (".config/r2frida/plugins/");
		newfile = r_str_concatf (newfile, "%s.js", str);
		fd = r_sandbox_fopen (newfile, "rb");
		free (newfile);
		if (!fd) {
			return NULL;
		}
	}
        (void)fseek (fd, 0, SEEK_END);
        sz = ftell (fd);
        if (!sz) {
                if (r_file_is_regular (str)) {
                        /* proc file */
                        fseek (fd, 0, SEEK_SET);
                        sz = ftell (fd);
                        if (!sz) {
                                sz = -1;
                        }
                } else {
                        sz = 65536;
                }
        }
        if (sz < 0) {
                fclose (fd);
                return NULL;
        }
        (void)fseek (fd, 0, SEEK_SET);
        ret = (char *)calloc (sz + 1, 1);
        if (!ret) {
                fclose (fd);
                return NULL;
        }
        rsz = fread (ret, 1, sz, fd);
        if (rsz != sz) {
                // eprintf ("r_file_slurp: fread: error\n");
                sz = rsz;
        }
        fclose (fd);
        ret[sz] = '\0';
        if (usz) {
                *usz = (int)sz;
        }
        return ret;
}

static RIOFrida *r_io_frida_new(void) {
	RIOFrida *rf = R_NEW0 (RIOFrida);
	if (!rf) {
		return NULL;
	}

	rf->detached = false;
	rf->detach_reason = FRIDA_SESSION_DETACH_REASON_APPLICATION_REQUESTED;
	rf->received_reply = false;

	return rf;
}

static void r_io_frida_free(RIOFrida *rf) {
	if (!rf) {
		return;
	}

	g_clear_object (&rf->script);
	g_clear_object (&rf->session);
	g_clear_object (&rf->device);

	if (rf->manager) {
		frida_device_manager_close_sync (rf->manager);
		g_object_unref (rf->manager);
		rf->manager = NULL;
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

	frida_init ();

	rf = r_io_frida_new ();
	if (!rf) {
		goto error;
	}

	rf->manager = frida_device_manager_new ();

	if (!__check (io, pathname, false)) {
		goto error;
	}

	if (!parse_target (pathname, &device_id, &process_specifier)) {
		goto error;
	}

	if (!resolve_device (rf->manager, device_id, &rf->device)) {
		goto error;
	}

	if (!resolve_process (rf->device, process_specifier, &pid)) {
		goto error;
	}

	rf->pid = pid;
	rf->session = frida_device_attach_sync (rf->device, pid, &error);
	if (error) {
		eprintf ("Cannot attach: %s\n", error->message);
		goto error;
	}

	rf->script = frida_session_create_script_sync (rf->session, "r2io", r_io_frida_agent_code, &error);
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

	RETURN_IO_DESC_NEW (&r_io_plugin_frida, -1, pathname, rw, mode, rf);

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

	r_io_frida_free (fd->data);
	fd->data = NULL;
	fd->state = R_IO_DESC_TYPE_CLOSED;

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

static int __system(RIO *io, RIODesc *fd, const char *command) {
	RIOFrida *rf;
	JsonBuilder *builder;
	JsonObject *result;
	const char *value;

	if (!fd || !fd->data) {
		return -1;
	}

	if (!strcmp (command, "help") || !strcmp (command, "h") || !strcmp (command, "?")) {
		io->cb_printf ("r2frida commands available via =!\n"
			"?                          Show this help\n"
			"?V                         Show target Frida version\n"
			"i                          Show target information\n"
			"ii[*]                      List imports\n"
			"il                         List libraries\n"
			"ie[*] <lib>                List exports/entrypoints of lib\n"
			"is[*] (<lib>) <sym>        Show address of symbol\n"
			"ic <class>                 List Objective-C classes or methods of <class>\n"
			"ip <protocol>              List Objective-C protocols or methods of <protocol>\n"
			"fd[*j] <address>           Inverse symbol resolution\n"
			"dd[-][fd] ([newfd])        List, dup2 or close filedescriptors\n"
			"dm[.|j|*]                  Show memory regions\n"
			"dma <size>                 Allocate <size> bytes on the heap, address is returned\n"
			"dmas <string>              Allocate a string inited with <string> on the heap\n"
			"dmad <addr> <size>         Allocate <size> bytes on the heap, copy contents from <addr>\n"
			"dmal                       List live heap allocations created with dma[s]\n"
			"dma- (<addr>...)           Kill the allocations at <addr> (or all of them without param)\n"
			"dmp <addr> <size> <perms>  Change page at <address> with <size>, protection <perms> (rwx)\n"
			"dp                         Show current pid\n"
			"dpt                        Show threads\n"
			"dr                         Show thread registers (see dpt)\n"
			"env [k[=v]]                Get/set environment variable\n"
			"dl libname                 Dlopen a library\n"
			"dl2 libname [main]         Inject library using Frida's >= 8.2 new API\n"
			"dt <addr> ..               Trace list of addresses\n"
			"dt-                        Clear all tracing\n"
			"dtr <addr> (<regs>...)     Trace register values\n"
			"dtf <addr> [fmt]           Trace address with format (^ixz) (see dtf?)\n"
			"di[0,1,-1] [addr]          Intercept and replace return value of address\n"
			"dx [hexpairs]              Inject code and execute it (TODO)\n"
			"dxc [sym|addr] [args..]    Call the target symbol with given args\n"
			". script                   Run script\n"
			"<space> code..             Evaluate Cycript code\n"
			"eval code..                Evaluate Javascript code in agent side\n"
			);
		return true;
	}

	rf = fd->data;
	if (!strncmp (command, "dtf?", 4)) {
		io->cb_printf ("Usage: dtf [format] || dtf [addr] [fmt]\n");
		io->cb_printf ("  ^  = trace onEnter instead of onExit\n");
		io->cb_printf ("  +  = show backtrace on trace\n");
		io->cb_printf ("  x  = show hexadecimal argument\n");
		io->cb_printf ("  i  = show decimal argument\n");
		io->cb_printf ("  z  = show pointer to string\n");
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
		return true;
	}
	char *slurpedData = NULL;
	if (command[0] == '.') {
		switch (command[1]) {
		case ' ':
			slurpedData = slurpFile (command + 2, NULL);
			if (!slurpedData) {
				io->cb_printf ("Cannot slurp %s\n", command + 2);
				return false;
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
#if WITH_CYCRIPT
			js = cylang_compile (command + 1, &error);
			if (error) {
				io->cb_printf ("ERROR: %s\n", error->message);
				g_error_free (error);
				return -1;
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

	/* update seek in agent */
	{
		char offstr[127] = {0};
		JsonBuilder *builder = build_request ("seek");
		json_builder_set_member_name (builder, "offset");
		snprintf (offstr, sizeof (offstr), "0x%"PFMT64x, io->off);
		json_builder_add_string_value (builder, offstr);
		JsonObject *result = perform_request (rf, builder, NULL, NULL);
		if (!result) {
			return -1;
		}
		json_object_unref (result);
	}

	result = perform_request (rf, builder, NULL, NULL);
	if (!result) {
		return -1;
	}
	value = json_object_get_string_member (result, "value");
	if (value && strcmp (value, "undefined")) {
		io->cb_printf ("%s\n", value);
	}
	json_object_unref (result);

	return 0;
}

static bool parse_target(const char *pathname, char **device_id, char **process_specifier) {
	const char *first_field, *second_field;

	first_field = pathname + 8;
	if (*first_field == '/') {
		eprintf ("r2frida: Spawning is not yet supported\n");
		return false;
	}
	second_field = strchr (first_field, '/');
	if (!second_field) {
		*device_id = NULL;
		*process_specifier = g_strdup (first_field);
		return true;
	}
	second_field++;

	*device_id = g_strndup (first_field, second_field - first_field - 1);
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

	while (!rf->detached && !rf->received_reply) {
		g_cond_wait (&rf->cond, &rf->lock);
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

static void on_stanza(RIOFrida *rf, JsonObject *stanza, GBytes *bytes) {
	g_mutex_lock (&rf->lock);

	g_assert (!rf->reply_stanza && !rf->reply_bytes);

	rf->received_reply = true;
	rf->reply_stanza = stanza;
	rf->reply_bytes = (bytes != NULL) ? g_bytes_ref (bytes) : NULL;

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
		on_stanza (rf,
			json_object_ref (json_object_get_object_member (root, "payload")),
			data);
	} else if (!strcmp (type, "log")) {
		eprintf ("%s\n", json_object_get_string_member (root, "payload"));
	} else {
		eprintf ("Unhandled message: %s\n", message);
	}

	g_object_unref (parser);
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
