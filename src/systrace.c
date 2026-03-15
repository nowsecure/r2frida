/* radare2 - MIT - Copyright 2026 - pancake, oleavr */

#define R_LOG_ORIGIN "r2frida"

#include "systrace.h"

typedef enum {
	SYS_ABI_NATIVE = 1,
	SYS_ABI_COMPAT32,
} SysAbi;

typedef struct {
	guint pid;
	guint64 tid;
	guint64 time_ns;
	int nr;
} SysId;

typedef struct {
	SysId id;
	SysAbi abi;
	char *name;
	GVariant *payload;
	bool enter;
} SysEvent;

typedef struct {
	guint pid;
	SysAbi abi;
} SysProc;

static const char *abi_name(SysAbi abi) {
	return abi == SYS_ABI_COMPAT32? "compat32": "native";
}

static SysAbi abi_parse(const char *abi) {
	return !strcmp (abi, "compat32")? SYS_ABI_COMPAT32: SYS_ABI_NATIVE;
}

static void clear_match(R2FSystraceState *st) {
	R_FREE (st->match_names);
	g_clear_pointer (&st->match_regex, g_regex_unref);
}

static void clear_sigs(R2FSystraceState *st) {
	g_clear_pointer (&st->sigs_native, g_hash_table_unref);
	g_clear_pointer (&st->sigs_compat32, g_hash_table_unref);
}

static void state_init(R2FSystraceState *st) {
	memset (st, 0, sizeof (*st));
	g_mutex_init (&st->lock);
	st->pid_abis = g_hash_table_new (g_direct_hash, g_direct_equal);
}

static void state_fini(R2FSystraceState *st) {
	g_clear_object (&st->service);
	g_clear_pointer (&st->pid_abis, g_hash_table_unref);
	clear_match (st);
	clear_sigs (st);
	g_mutex_clear (&st->lock);
}

void r2f_systrace_init(RIOFrida *rf) {
	state_init (&rf->systrace);
}

static void set_match(R2FSystraceState *st, const char *match) {
	clear_match (st);
	if (R_STR_ISEMPTY (match)) {
		return;
	}
	if (*match == '/') {
		const char *body = match + 1;
		const char *tail = strrchr (body, '/');
		char *pat = (tail && tail > body)? g_strndup (body, tail - body): strdup (body);
		GError *error = NULL;
		st->match_regex = g_regex_new (pat, G_REGEX_OPTIMIZE, 0, &error);
		if (error) {
			R_LOG_ERROR ("Invalid systrace.match regex: %s", error->message);
			g_clear_error (&error);
		}
		free (pat);
		return;
	}
	RStrBuf *sb = r_strbuf_new (",");
	char **names = g_strsplit (match, ",", -1);
	for (char **it = names; it && *it; it++) {
		char *trimmed = g_strstrip (*it);
		if (R_STR_ISNOTEMPTY (trimmed)) {
			char *lower = g_ascii_strdown (trimmed, -1);
			r_strbuf_appendf (sb, "%s,", lower);
			g_free (lower);
		}
	}
	g_strfreev (names);
	char *serialized = r_strbuf_drain (sb);
	if (serialized && strcmp (serialized, ",")) {
		st->match_names = serialized;
	} else {
		free (serialized);
	}
}

static bool name_matches(const R2FSystraceState *st, const char *name) {
	if (st->match_regex) {
		return g_regex_match (st->match_regex, name, 0, NULL);
	}
	if (!st->match_names) {
		return true;
	}
	if (R_STR_ISEMPTY (name)) {
		return false;
	}
	char *lower = g_ascii_strdown (name, -1);
	char *needle = g_strdup_printf (",%s,", lower);
	bool found = strstr (st->match_names, needle) != NULL;
	g_free (needle);
	g_free (lower);
	return found;
}

static GVariant *request(RIOFrida *rf, GVariant *params) {
	GError *error = NULL;
	params = g_variant_ref_sink (params);
	GVariant *result = frida_service_request_sync (rf->systrace.service, params, rf->cancellable, &error);
	g_variant_unref (params);
	if (error) {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			R_LOG_ERROR ("syscall tracer request failed: %s", error->message);
		}
		g_clear_error (&error);
		return NULL;
	}
	return result;
}

static GVariant *request_type(RIOFrida *rf, const char *type) {
	GVariantBuilder b;
	g_variant_builder_init (&b, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&b, "{sv}", "type", g_variant_new_string (type));
	return request (rf, g_variant_builder_end (&b));
}

static GHashTable *build_name_table(GVariant *table) {
	GHashTable *ht = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, g_free);
	GVariantIter it;
	GVariant *item;
	g_variant_iter_init (&it, table);
	while ((item = g_variant_iter_next_value (&it))) {
		int nr;
		const char *name;
		g_variant_get_child (item, 0, "i", &nr);
		g_variant_get_child (item, 1, "&s", &name);
		g_hash_table_replace (ht, GINT_TO_POINTER (nr), g_strdup (name));
		g_variant_unref (item);
	}
	return ht;
}

static const char *lookup_name(const R2FSystraceState *st, SysAbi abi, int nr) {
	GHashTable *ht = abi == SYS_ABI_COMPAT32? st->sigs_compat32: st->sigs_native;
	return ht? g_hash_table_lookup (ht, GINT_TO_POINTER (nr)): NULL;
}

static void event_init(const R2FSystraceState *st, GVariant *row, SysEvent *ev) {
	const char *phase;
	memset (ev, 0, sizeof (*ev));
	g_variant_get_child (row, 0, "&s", &phase);
	g_variant_get_child (row, 1, "t", &ev->id.time_ns);
	g_variant_get_child (row, 2, "t", &ev->id.tid);
	g_variant_get_child (row, 3, "u", &ev->id.pid);
	g_variant_get_child (row, 4, "i", &ev->id.nr);
	ev->payload = g_variant_get_child_value (row, 7);
	ev->enter = !strcmp (phase, "enter");
	ev->abi = GPOINTER_TO_UINT (g_hash_table_lookup (st->pid_abis, GUINT_TO_POINTER (ev->id.pid)));
	if (!ev->abi) {
		ev->abi = SYS_ABI_NATIVE;
	}
	const char *sig = lookup_name (st, ev->abi, ev->id.nr);
	ev->name = sig? g_strdup (sig): g_strdup_printf ("#%d", ev->id.nr);
}

static void event_fini(SysEvent *ev) {
	g_clear_pointer (&ev->payload, g_variant_unref);
	R_FREE (ev->name);
}

static void post_log(RIOFrida *rf, const SysEvent *ev, const char *retval, bool failed) {
	if (!rf->script) {
		return;
	}
	char tid[64];
	char timebuf[64];
	snprintf (tid, sizeof (tid), "%" PFMT64u, (ut64)ev->id.tid);
	snprintf (timebuf, sizeof (timebuf), "%" PFMT64u, (ut64)ev->id.time_ns);
	PJ *j = pj_new ();
	pj_o (j);
	pj_ks (j, "type", "systrace-log");
	pj_ko (j, "payload");
	pj_ks (j, "phase", ev->enter? "enter": "exit");
	pj_kn (j, "pid", ev->id.pid);
	pj_ks (j, "tid", tid);
	pj_ks (j, "abi", abi_name (ev->abi));
	pj_ki (j, "nr", ev->id.nr);
	pj_ks (j, "name", ev->name);
	pj_ks (j, "timeNs", timebuf);
	pj_ka (j, ev->enter? "args": "outArgs");
	if (ev->enter) {
		guint argc = g_variant_n_children (ev->payload);
		for (guint i = 0; i < argc; i++) {
			guint64 raw;
			char arg[64];
			g_variant_get_child (ev->payload, i, "t", &raw);
			snprintf (arg, sizeof (arg), "arg%u=0x%" PFMT64x, i, (ut64)raw);
			pj_s (j, arg);
		}
	}
	pj_end (j);
	if (!ev->enter) {
		pj_ks (j, "retval", retval? retval: "0");
		pj_kb (j, "failed", failed);
	}
	pj_end (j);
	pj_end (j);
	char *msg = pj_drain (j);
	frida_script_post (rf->script, msg, NULL);
	free (msg);
}

static void handle_event(RIOFrida *rf, GVariant *row) {
	SysEvent ev;
	event_init (&rf->systrace, row, &ev);
	if (name_matches (&rf->systrace, ev.name)) {
		if (ev.enter) {
			post_log (rf, &ev, NULL, false);
		} else {
			gint64 ret = g_variant_get_int64 (ev.payload);
			char *retval = g_strdup_printf ("%" PFMT64d, (st64)ret);
			post_log (rf, &ev, retval, ret < 0);
			g_free (retval);
		}
	}
	event_fini (&ev);
}

static void update_pid_abis(R2FSystraceState *st, GVariant *procs) {
	GVariantIter it;
	GVariant *item;
	g_variant_iter_init (&it, procs);
	while ((item = g_variant_iter_next_value (&it))) {
		SysProc proc;
		const char *abi;
		g_variant_get_child (item, 0, "u", &proc.pid);
		g_variant_get_child (item, 1, "&s", &abi);
		proc.abi = abi_parse (abi);
		g_hash_table_replace (st->pid_abis, GUINT_TO_POINTER (proc.pid), GUINT_TO_POINTER (proc.abi));
		g_variant_unref (item);
	}
}

static bool load_signatures(RIOFrida *rf) {
	R2FSystraceState *st = &rf->systrace;
	GVariant *result = request_type (rf, "get-signatures");
	if (!result) {
		return false;
	}
	GVariant *native = g_variant_lookup_value (result, "native", G_VARIANT_TYPE ("a(isa(ss))"));
	GVariant *compat32 = g_variant_lookup_value (result, "compat32", G_VARIANT_TYPE ("a(isa(ss))"));
	clear_sigs (st);
	if (native) {
		st->sigs_native = build_name_table (native);
		g_variant_unref (native);
	}
	if (compat32) {
		st->sigs_compat32 = build_name_table (compat32);
		g_variant_unref (compat32);
	}
	g_variant_unref (result);
	return st->sigs_native != NULL;
}

static void read_events(RIOFrida *rf) {
	R2FSystraceState *st = &rf->systrace;
	while (st->service) {
		GVariant *result = request_type (rf, "read-events");
		if (!result) {
			return;
		}
		GVariant *events = g_variant_lookup_value (result, "events", G_VARIANT_TYPE ("av"));
		GVariant *procs = g_variant_lookup_value (result, "processes", G_VARIANT_TYPE ("a(us)"));
		const char *status = NULL;
		g_variant_lookup (result, "status", "&s", &status);
		if (procs) {
			update_pid_abis (st, procs);
			g_variant_unref (procs);
		}
		if (events) {
			GVariantIter it;
			GVariant *item;
			g_variant_iter_init (&it, events);
			while ((item = g_variant_iter_next_value (&it))) {
				GVariant *row = g_variant_get_variant (item);
				handle_event (rf, row);
				g_variant_unref (row);
				g_variant_unref (item);
			}
			g_variant_unref (events);
		}
		bool more = status && !strcmp (status, "more");
		g_variant_unref (result);
		if (!more) {
			break;
		}
	}
}

static bool start(RIOFrida *rf) {
	R2FSystraceState *st = &rf->systrace;
	if (st->service) {
		return true;
	}
	GError *error = NULL;
	st->service = frida_device_open_service_sync (rf->device, "syscall-trace", rf->cancellable, &error);
	if (error) {
		R_LOG_ERROR ("Cannot open syscall-trace service: %s", error->message);
		g_clear_error (&error);
		g_clear_object (&st->service);
		return false;
	}
	frida_service_activate_sync (st->service, rf->cancellable, &error);
	if (error) {
		R_LOG_ERROR ("Cannot activate syscall-trace service: %s", error->message);
		g_clear_error (&error);
		g_clear_object (&st->service);
		return false;
	}
	if (!load_signatures (rf)) {
		g_clear_object (&st->service);
		return false;
	}
	st->handler = g_signal_connect (st->service, "message", G_CALLBACK (on_systrace_message), rf);
	GVariantBuilder b;
	GVariantBuilder pids;
	g_variant_builder_init (&b, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&b, "{sv}", "type", g_variant_new_string ("add-targets"));
	g_variant_builder_init (&pids, G_VARIANT_TYPE ("av"));
	g_variant_builder_add (&pids, "v", g_variant_new_int64 ((gint64)rf->pid));
	g_variant_builder_add (&b, "{sv}", "pids", g_variant_builder_end (&pids));
	GVariant *result = request (rf, g_variant_builder_end (&b));
	if (!result) {
		g_signal_handler_disconnect (st->service, st->handler);
		st->handler = 0;
		g_clear_object (&st->service);
		return false;
	}
	g_variant_unref (result);
	return true;
}

static void stop(RIOFrida *rf) {
	R2FSystraceState *st = &rf->systrace;
	if (st->service && st->handler) {
		g_signal_handler_disconnect (st->service, st->handler);
		st->handler = 0;
	}
	if (st->service) {
		GError *error = NULL;
		frida_service_cancel_sync (st->service, rf->cancellable, &error);
		if (error && !g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			R_LOG_ERROR ("Cannot stop syscall-trace service: %s", error->message);
		}
		g_clear_error (&error);
		g_clear_object (&st->service);
	}
	g_hash_table_remove_all (st->pid_abis);
}

void r2f_systrace_configure(RIOFrida *rf, bool enabled, const char *match) {
	R2FSystraceState *st = &rf->systrace;
	g_mutex_lock (&st->lock);
	set_match (st, match);
	if (enabled) {
		(void)start (rf);
	} else {
		stop (rf);
	}
	g_mutex_unlock (&st->lock);
}

void r2f_systrace_fini(RIOFrida *rf) {
	R2FSystraceState *st = &rf->systrace;
	g_mutex_lock (&st->lock);
	stop (rf);
	clear_match (st);
	clear_sigs (st);
	g_mutex_unlock (&st->lock);
	state_fini (st);
}

void on_systrace_message(FridaService *service, GVariant *message, gpointer user_data) {
	(void)service;
	RIOFrida *rf = user_data;
	const char *type = NULL;
	if (!g_variant_lookup (message, "type", "&s", &type) || strcmp (type, "events-available")) {
		return;
	}
	g_mutex_lock (&rf->systrace.lock);
	read_events (rf);
	g_mutex_unlock (&rf->systrace.lock);
}
