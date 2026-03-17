/* radare2 - MIT - Copyright 2026 - pancake, oleavr */

#define R_LOG_ORIGIN "r2frida"

#include "io_frida.h"

extern RIOPlugin r_io_plugin_frida;
static void stop(RIOFrida *rf);
static bool start(RIOFrida *rf);

typedef enum {
	SYS_ABI_NATIVE,
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
	char **param_names;
	int n_params;
	GVariant *payload;
	bool enter;
} SysEvent;

static gboolean string_equal(gconstpointer a, gconstpointer b) {
	return !strcmp ((const char *)a, (const char *)b);
}

static void clear_pending_matches(R2FSystraceState *st) {
	if (st->pending) {
		g_hash_table_remove_all (st->pending);
	}
}

void r2f_systrace_init(RIOFrida *rf) {
	R2FSystraceState *st = &rf->systrace;
	memset (st, 0, sizeof (*st));
	st->pending = g_hash_table_new_full (g_str_hash, string_equal, g_free, NULL);
}

static void configure(RIOFrida *rf);
static bool config_systrace_enable(void *user, void *data);
static bool config_systrace_match(void *user, void *data);
static bool config_systrace_filter(void *user, void *data);
static bool config_systrace_tid(void *user, void *data);

static void scsig_clear(SCSig *s) {
	if (!s || !s->name) {
		return;
	}
	g_free (s->name);
	g_strfreev (s->param_names);
	memset (s, 0, sizeof (*s));
}

static void scsig_reset(R2FSystraceState *st) {
	for (int i = 0; i < st->scsig_len; i++) {
		scsig_clear (&st->scsig[i]);
	}
	g_clear_pointer (&st->scsig, g_free);
	st->scsig_len = 0;
}

static void state_fini(R2FSystraceState *st) {
	g_clear_object (&st->service);
	g_clear_pointer (&st->pending, g_hash_table_unref);
	g_clear_pointer (&st->match_regex, g_regex_unref);
	g_clear_pointer (&st->filter_regex, g_regex_unref);
	scsig_reset (st);
}

R_IPI void r2f_systrace_config_init(RIOFrida *rf) {
	RConfig *cfg = rf->r2core->config;
	RConfigNode *cn = r_config_set_b (cfg, "r2frida.systrace.enable", false);
	if (!cn) {
		R_LOG_ERROR ("Cannot create keys");
		return;
	}
	r_config_set_setter (cfg, "r2frida.systrace.enable", config_systrace_enable);
	r_config_node_desc (cn, "Enable syscall tracing");
	cn = r_config_set (cfg, "r2frida.systrace.match", "");
	r_config_set_setter (cfg, "r2frida.systrace.match", config_systrace_match);
	r_config_node_desc (cn, "Filter syscall names using plain text, commas, or /regex/");
	cn = r_config_set (cfg, "r2frida.systrace.filter", "");
	r_config_set_setter (cfg, "r2frida.systrace.filter", config_systrace_filter);
	r_config_node_desc (cn, "Filter rendered syscall text using plain text or /regex/");

	r_strf_var (pid, 32, "%u", rf->pid);
	cn = r_config_set (cfg, "r2frida.systrace.tid", pid);
	r_config_set_setter (cfg, "r2frida.systrace.tid", config_systrace_tid);
	r_config_node_desc (cn, "Filter systrace events to a tid, use 0 to disable it");
	configure (rf);
}

void r2f_systrace_config_fini(RIOFrida *rf) {
	RConfig *cfg = rf->r2core->config;
	r_config_rm (cfg, "r2frida.systrace.enable");
	r_config_rm (cfg, "r2frida.systrace.match");
	r_config_rm (cfg, "r2frida.systrace.filter");
	r_config_rm (cfg, "r2frida.systrace.tid");
}

static void set_match(R2FSystraceState *st, const char *match) {
	GRegexCompileFlags flags = G_REGEX_OPTIMIZE;
	g_clear_pointer (&st->match_regex, g_regex_unref);
	if (R_STR_ISEMPTY (match)) {
		return;
	}
	char *pattern;
	if (*match == '/') {
		size_t len = strlen (match);
		pattern = (len > 2 && match[len - 1] == '/')
			? r_str_ndup (match + 1, len - 2)
			: strdup (match + 1);
	} else {
		char *s = r_str_replace_all (strdup (match), ",", "|");
		pattern = r_str_newf ("^(%s)$", s);
		free (s);
		flags |= G_REGEX_CASELESS;
	}
	GError *error = NULL;
	st->match_regex = g_regex_new (pattern, flags, 0, &error);
	if (error) {
		R_LOG_ERROR ("Invalid systrace.match regex: %s", error->message);
		g_clear_error (&error);
	}
	free (pattern);
}

static void set_filter(R2FSystraceState *st, const char *filter) {
	g_clear_pointer (&st->filter_regex, g_regex_unref);
	if (R_STR_ISEMPTY (filter)) {
		return;
	}
	char *pattern;
	GRegexCompileFlags flags = G_REGEX_OPTIMIZE;
	if (*filter == '/') {
		size_t len = strlen (filter);
		pattern = (len > 2 && filter[len - 1] == '/')
			? r_str_ndup (filter + 1, len - 2)
			: strdup (filter + 1);
	} else {
		pattern = g_regex_escape_string (filter, -1);
		flags |= G_REGEX_CASELESS;
	}
	GError *error = NULL;
	st->filter_regex = g_regex_new (pattern, flags, 0, &error);
	if (error) {
		R_LOG_ERROR ("Invalid systrace.filter regex: %s", error->message);
		g_clear_error (&error);
	}
	free (pattern);
}

static bool name_matches(const R2FSystraceState *st, const char *name) {
	if (!st->match_regex) {
		return true;
	}
	return R_STR_ISNOTEMPTY (name) && g_regex_match (st->match_regex, name, 0, NULL);
}

static bool text_matches(const R2FSystraceState *st, const char *text) {
	if (!st->filter_regex) {
		return true;
	}
	return R_STR_ISNOTEMPTY (text) && g_regex_match (st->filter_regex, text, 0, NULL);
}

static bool validate_regex(const char *name, const char *value) {
	if (R_STR_ISEMPTY (value) || *value != '/') {
		return true;
	}
	size_t len = strlen (value);
	char *pattern = (len > 2 && value[len - 1] == '/')
		? r_str_ndup (value + 1, len - 2)
		: strdup (value + 1);
	GError *error = NULL;
	GRegex *regex = g_regex_new (pattern, G_REGEX_OPTIMIZE, 0, &error);
	free (pattern);
	g_clear_pointer (&regex, g_regex_unref);
	if (error) {
		R_LOG_ERROR ("Invalid %s regex: %s", name, error->message);
		g_clear_error (&error);
		return false;
	}
	return true;
}

static void configure(RIOFrida *rf) {
	R2FSystraceState *st = &rf->systrace;
	RConfig *cfg = rf->r2core->config;
	const bool enabled = r_config_get_b (cfg, "r2frida.systrace.enable");
	const char *match = r_config_get (cfg, "r2frida.systrace.match");
	const char *filter = r_config_get (cfg, "r2frida.systrace.filter");
	const char *tid = r_config_get (cfg, "r2frida.systrace.tid");
	stop (rf);
	set_match (st, match);
	set_filter (st, filter);
	st->has_pid_filter = rf->pid != 0;
	st->pid_filter = rf->pid;
	if (R_STR_ISNOTEMPTY (tid)) {
		ut64 v = r_num_get (rf->r2core->num, tid);
		st->has_tid_filter = v != 0;
		st->tid_filter = v;
	} else {
		st->has_tid_filter = false;
		st->tid_filter = 0;
	}
	clear_pending_matches (st);
	if (enabled) {
		(void)start (rf);
	}
}

static RIOFrida *get_riofrida(void *user) {
	RCore *core = user;
	RIOFrida *fallback = NULL;
	RIODesc *desc = r_io_desc_get_lowest (core->io);
	while (desc) {
		if (desc->plugin == &r_io_plugin_frida && desc->data) {
			if (desc == core->io->desc) {
				return desc->data;
			}
			if (!fallback) {
				fallback = desc->data;
			}
		}
		desc = r_io_desc_get_next (core->io, desc);
	}
	return fallback;
}

static bool config_systrace_enable(void *user, void *data) {
	(void)data;
	RIOFrida *rf = get_riofrida (user);
	if (rf) {
		configure (rf);
	}
	return true;
}

static bool config_systrace_match(void *user, void *data) {
	RConfigNode *cn = data;
	RIOFrida *rf = get_riofrida (user);
	if (rf) {
		if (!validate_regex ("r2frida.systrace.match", cn->value)) {
			return false;
		}
		configure (rf);
	}
	return true;
}

static bool config_systrace_filter(void *user, void *data) {
	RConfigNode *cn = data;
	RIOFrida *rf = get_riofrida (user);
	if (rf) {
		if (!validate_regex ("r2frida.systrace.filter", cn->value)) {
			return false;
		}
		configure (rf);
	}
	return true;
}

static bool config_systrace_tid(void *user, void *data) {
	(void)data;
	RIOFrida *rf = get_riofrida (user);
	if (rf) {
		configure (rf);
	}
	return true;
}

static bool event_matches(const R2FSystraceState *st, const SysEvent *ev) {
	if (st->has_pid_filter && ev->id.pid != st->pid_filter) {
		return false;
	}
	if (st->has_tid_filter && ev->id.tid != st->tid_filter) {
		return false;
	}
	return name_matches (st, ev->name);
}

static GVariant *request_service(FridaService *service, GCancellable *cancellable, GVariant *params) {
	GError *error = NULL;
	params = g_variant_ref_sink (params);
	GVariant *result = frida_service_request_sync (service, params, cancellable, &error);
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

static GVariant *request_type(RIOFrida *rf, FridaService *service, const char *type) {
	GVariantBuilder b;
	g_variant_builder_init (&b, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&b, "{sv}", "type", g_variant_new_string (type));
	return request_service (service, rf->cancellable, g_variant_builder_end (&b));
}

static void load_scsig_table(R2FSystraceState *st, GVariant *table, SysAbi abi) {
	GVariantIter it;
	GVariant *item;
	g_variant_iter_init (&it, table);
	while ((item = g_variant_iter_next_value (&it))) {
		int nr;
		const char *name;
		g_variant_get_child (item, 0, "i", &nr);
		if (nr < 0) {
			g_variant_unref (item);
			continue;
		}
		int key = (nr << 1) | abi;
		if (key >= st->scsig_len) {
			int new_len = key + 64;
			st->scsig = g_realloc (st->scsig, new_len * sizeof (SCSig));
			memset (st->scsig + st->scsig_len, 0, (new_len - st->scsig_len) * sizeof (SCSig));
			st->scsig_len = new_len;
		}
		SCSig *s = &st->scsig[key];
		scsig_clear (s);
		g_variant_get_child (item, 1, "&s", &name);
		s->name = g_strdup (name);
		GVariant *params = g_variant_get_child_value (item, 2);
		s->n_params = (int)g_variant_n_children (params);
		s->param_names = g_new0 (char *, s->n_params + 1);
		for (int i = 0; i < s->n_params; i++) {
			GVariant *p = g_variant_get_child_value (params, i);
			const char *pname;
			g_variant_get_child (p, 0, "&s", &pname);
			s->param_names[i] = g_strdup (pname);
			g_variant_unref (p);
		}
		g_variant_unref (params);
		g_variant_unref (item);
	}
}

static const SCSig *lookup_scsig(const R2FSystraceState *st, SysAbi abi, int nr) {
	int key = nr < 0? -1: (nr << 1) | abi;
	return (key >= 0 && key < st->scsig_len && st->scsig[key].name)? &st->scsig[key]: NULL;
}

static SysEvent event_init(const RIOFrida *rf, GVariant *row) {
	SysEvent ev = {0};
	const R2FSystraceState *st = &rf->systrace;
	const char *phase;
	g_variant_get_child (row, 0, "&s", &phase);
	g_variant_get_child (row, 1, "t", &ev.id.time_ns);
	g_variant_get_child (row, 2, "t", &ev.id.tid);
	g_variant_get_child (row, 3, "u", &ev.id.pid);
	g_variant_get_child (row, 4, "i", &ev.id.nr);
	ev.payload = g_variant_get_child_value (row, 7);
	ev.enter = !strcmp (phase, "enter");
	ev.abi = ev.id.pid == rf->pid && st->target_compat32? SYS_ABI_COMPAT32: SYS_ABI_NATIVE;
	const SCSig *scsig = lookup_scsig (st, ev.abi, ev.id.nr);
	ev.name = scsig? g_strdup (scsig->name): g_strdup_printf ("#%d", ev.id.nr);
	if (scsig) {
		ev.param_names = scsig->param_names;
		ev.n_params = scsig->n_params;
	}
	return ev;
}

static void event_fini(SysEvent *ev) {
	g_clear_pointer (&ev->payload, g_variant_unref);
	R_FREE (ev->name);
}

static char *event_key(const SysEvent *ev) {
	return g_strdup_printf ("%u:%" PFMT64u, ev->id.pid, (ut64)ev->id.tid);
}

static char *format_enter_args(const SysEvent *ev) {
	RStrBuf *args = r_strbuf_new ("[");
	const guint argc = g_variant_n_children (ev->payload);
	for (guint i = 0; i < argc; i++) {
		guint64 raw;
		if (i > 0) {
			r_strbuf_append (args, ", ");
		}
		g_variant_get_child (ev->payload, i, "t", &raw);
		r_strbuf_appendf (args, "0x%" PFMT64x, (ut64)raw);
	}
	r_strbuf_append (args, "]");
	return r_strbuf_drain (args);
}

static char *format_exit_retval(const SysEvent *ev, bool *failed) {
	const gint64 ret = g_variant_get_int64 (ev->payload);
	*failed = ret < 0;
	return g_strdup_printf ("%" PFMT64d, (st64)ret);
}

static bool should_log_event(R2FSystraceState *st, const SysEvent *ev, const char *text) {
	char *key = event_key (ev);
	const bool matched = text_matches (st, text);
	const bool was_pending = st->pending? g_hash_table_lookup (st->pending, key) != NULL: false;
	bool should_log = matched;
	if (ev->enter) {
		if (matched) {
			g_hash_table_replace (st->pending, key, GINT_TO_POINTER (1));
			key = NULL;
		} else {
			g_hash_table_remove (st->pending, key);
		}
	} else {
		if (was_pending) {
			g_hash_table_remove (st->pending, key);
			should_log = true;
		}
	}
	g_free (key);
	return should_log;
}

static void emit_json_log(const SysEvent *ev, const char *enter_args, const char *retval, bool failed) {
	r_strf_var (tid, 32, "%" PFMT64u, (ut64)ev->id.tid);
	r_strf_var (timebuf, 32, "%" PFMT64u, (ut64)ev->id.time_ns);
	PJ *j = pj_new ();
	pj_o (j);
	pj_ks (j, "source", "systrace");
	pj_ks (j, "phase", ev->enter? "enter": "exit");
	pj_ks (j, "name", ev->name);
	pj_ki (j, "nr", ev->id.nr);
	pj_kn (j, "pid", ev->id.pid);
	pj_ks (j, "tid", tid);
	pj_ks (j, "abi", ev->abi == SYS_ABI_COMPAT32? "compat32": "native");
	pj_ks (j, "timeNs", timebuf);
	if (ev->enter) {
		if (enter_args) {
			pj_ks (j, "args", enter_args);
		}
		pj_ka (j, "values");
		const guint argc = g_variant_n_children (ev->payload);
		for (guint i = 0; i < argc; i++) {
			guint64 raw;
			char arg[64];
			g_variant_get_child (ev->payload, i, "t", &raw);
			snprintf (arg, sizeof (arg), "0x%" PFMT64x, (ut64)raw);
			pj_s (j, arg);
		}
		pj_end (j);
	} else {
		pj_ks (j, "retval", retval? retval: "0");
		pj_kb (j, "failed", failed);
	}
	pj_end (j);
	char *message = pj_drain (j);
	eprintf ("%s\n", message);
	free (message);
}

static void update_target_abi(R2FSystraceState *st, guint pid, GVariant *procs) {
	GVariantIter it;
	GVariant *item;
	g_variant_iter_init (&it, procs);
	while ((item = g_variant_iter_next_value (&it))) {
		guint item_pid;
		const char *abi;
		g_variant_get_child (item, 0, "u", &item_pid);
		if (item_pid == pid) {
			g_variant_get_child (item, 1, "&s", &abi);
			st->target_compat32 = !strcmp (abi, "compat32");
			g_variant_unref (item);
			return;
		}
		g_variant_unref (item);
	}
}

static bool load_signatures(RIOFrida *rf, FridaService *service) {
	R2FSystraceState *st = &rf->systrace;
	GVariant *result = request_type (rf, service, "get-signatures");
	if (!result) {
		return false;
	}
	GVariant *native = g_variant_lookup_value (result, "native", G_VARIANT_TYPE ("a(isa(ss))"));
	GVariant *compat32 = g_variant_lookup_value (result, "compat32", G_VARIANT_TYPE ("a(isa(ss))"));
	scsig_reset (st);
	bool ok = false;
	if (native) {
		load_scsig_table (st, native, SYS_ABI_NATIVE);
		g_variant_unref (native);
		ok = true;
	}
	if (compat32) {
		load_scsig_table (st, compat32, SYS_ABI_COMPAT32);
		g_variant_unref (compat32);
	}
	g_variant_unref (result);
	return ok;
}

static void process_events(RIOFrida *rf, FridaService *service, GVariant *events) {
	R2FSystraceState *st = &rf->systrace;
	GVariantIter it;
	GVariant *item;
	g_variant_iter_init (&it, events);
	while ((item = g_variant_iter_next_value (&it))) {
		GVariant *row = g_variant_get_variant (item);
		SysEvent ev = event_init (rf, row);
		if (st->service == service && event_matches (st, &ev)) {
			bool failed = false;
			char *retval = NULL;
			char *filter_text = NULL;
			if (ev.enter) {
				filter_text = format_enter_args (&ev);
			} else {
				retval = format_exit_retval (&ev, &failed);
				filter_text = strdup (retval);
			}
			if (should_log_event (st, &ev, filter_text)) {
				emit_json_log (&ev, ev.enter? filter_text: NULL, retval, failed);
			}
			g_free (filter_text);
			g_free (retval);
		}
		event_fini (&ev);
		g_variant_unref (row);
		g_variant_unref (item);
	}
}

static void schedule_read_events(RIOFrida *rf);

static void on_read_events_ready(GObject *source, GAsyncResult *result, gpointer user_data) {
	RIOFrida *rf = user_data;
	R2FSystraceState *st = &rf->systrace;
	FridaService *service = FRIDA_SERVICE (source);
	GError *error = NULL;
	GVariant *res = frida_service_request_finish (service, result, &error);
	if (error) {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			R_LOG_ERROR ("syscall tracer request failed: %s", error->message);
		}
		g_clear_error (&error);
		st->reading = false;
		st->read_pending = false;
		return;
	}
	if (st->service != service) {
		g_variant_unref (res);
		st->reading = false;
		st->read_pending = false;
		return;
	}
	GVariant *events = g_variant_lookup_value (res, "events", G_VARIANT_TYPE ("av"));
	GVariant *procs = g_variant_lookup_value (res, "processes", G_VARIANT_TYPE ("a(us)"));
	const char *status = NULL;
	g_variant_lookup (res, "status", "&s", &status);
	if (procs) {
		update_target_abi (st, rf->pid, procs);
		g_variant_unref (procs);
	}
	if (events) {
		process_events (rf, service, events);
		g_variant_unref (events);
	}
	bool more = status && !strcmp (status, "more");
	g_variant_unref (res);
	const bool schedule_next = st->service == service && (more || st->read_pending);
	st->read_pending = false;
	if (schedule_next) {
		schedule_read_events (rf);
	} else {
		st->reading = false;
	}
}

static void schedule_read_events(RIOFrida *rf) {
	R2FSystraceState *st = &rf->systrace;
	if (!st->service) {
		st->reading = false;
		return;
	}
	GVariantBuilder b;
	g_variant_builder_init (&b, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&b, "{sv}", "type", g_variant_new_string ("read-events"));
	GVariant *params = g_variant_ref_sink (g_variant_builder_end (&b));
	frida_service_request (st->service, params, rf->cancellable, on_read_events_ready, rf);
	g_variant_unref (params);
}

static gboolean on_read_events_idle(gpointer user_data) {
	RIOFrida *rf = user_data;
	R2FSystraceState *st = &rf->systrace;
	if (!st->reading && st->service) {
		st->reading = true;
		st->read_pending = false;
		schedule_read_events (rf);
	}
	return G_SOURCE_REMOVE;
}

static void stop(RIOFrida *rf) {
	R2FSystraceState *st = &rf->systrace;
	if (!st->service) {
		return;
	}
	FridaService *service = g_object_ref (st->service);
	gulong handler = st->handler;
	g_clear_object (&st->service);
	st->handler = 0;
	st->reading = false;
	st->read_pending = false;
	st->target_compat32 = false;
	clear_pending_matches (st);
	if (handler) {
		g_signal_handler_disconnect (service, handler);
	}
	GError *error = NULL;
	frida_service_cancel_sync (service, rf->cancellable, &error);
	if (error && !g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		R_LOG_ERROR ("Cannot stop syscall-trace service: %s", error->message);
	}
	g_clear_error (&error);
	g_object_unref (service);
}

static bool start(RIOFrida *rf) {
	R2FSystraceState *st = &rf->systrace;
	if (st->service) {
		return true;
	}
	GError *error = NULL;
	FridaService *service = frida_device_open_service_sync (rf->device, "syscall-trace", rf->cancellable, &error);
	if (error) {
		R_LOG_ERROR ("Cannot open syscall-trace service: %s", error->message);
		g_clear_error (&error);
		g_clear_object (&service);
		return false;
	}
	frida_service_activate_sync (service, rf->cancellable, &error);
	if (error) {
		R_LOG_ERROR ("Cannot activate syscall-trace service: %s", error->message);
		g_clear_error (&error);
		g_clear_object (&service);
		return false;
	}
	if (st->service) {
		g_object_unref (service);
		return true;
	}
	st->service = service;
	st->target_compat32 = false;
	if (!load_signatures (rf, service)) {
		stop (rf);
		return false;
	}
	if (st->service != service) {
		stop (rf);
		return false;
	}
	st->handler = g_signal_connect (service, "message", G_CALLBACK (on_systrace_message), rf);
	GVariantBuilder b;
	GVariantBuilder pids;
	g_variant_builder_init (&b, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&b, "{sv}", "type", g_variant_new_string ("add-targets"));
	g_variant_builder_init (&pids, G_VARIANT_TYPE ("av"));
	g_variant_builder_add (&pids, "v", g_variant_new_int64 ((gint64)rf->pid));
	g_variant_builder_add (&b, "{sv}", "pids", g_variant_builder_end (&pids));
	GVariant *result = request_service (st->service, rf->cancellable, g_variant_builder_end (&b));
	if (result) {
		g_variant_unref (result);
		return true;
	}
	stop (rf);
	return false;
}

void r2f_systrace_fini(RIOFrida *rf) {
	stop (rf);
	state_fini (&rf->systrace);
}

void on_systrace_message(FridaService *service, GVariant *message, gpointer user_data) {
	RIOFrida *rf = user_data;
	R2FSystraceState *st = &rf->systrace;
	const char *type = NULL;
	if (st->service != service || \
		!g_variant_lookup (message, "type", "&s", &type) || \
		strcmp (type, "events-available")) {
		return;
	}
	if (st->reading) {
		st->read_pending = true;
		return;
	}
	if (st->service) {
		GSource *source = g_idle_source_new ();
		g_source_set_callback (source, on_read_events_idle, rf, NULL);
		g_source_attach (source, frida_get_main_context ());
		g_source_unref (source);
	}
}
