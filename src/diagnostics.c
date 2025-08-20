// Shared diagnostics handling for Frida compiler
#include <r_util.h>
#include <r_util/pj.h>
#include <r_util/r_print.h>
#include <r_util/r_log.h>
#include "frida-core.h"
#include "diagnostics.h"

static const char *variant_get_str(GVariant *dict, const char *key) {
	if (!dict || !key) {
		return NULL;
	}
	GVariant *v = g_variant_lookup_value (dict, key, NULL);
	if (!v) {
		return NULL;
	}
	const char *res = NULL;
	if (g_variant_is_of_type (v, G_VARIANT_TYPE_STRING)) {
		res = g_variant_get_string (v, NULL);
	}
	g_variant_unref (v);
	return res;
}

static bool variant_get_int(GVariant *dict, const char *key, st64 *out) {
	if (!dict || !key || !out) {
		return false;
	}
	GVariant *v = g_variant_lookup_value (dict, key, NULL);
	if (!v) {
		return false;
	}
	bool ok = true;
	if (g_variant_is_of_type (v, G_VARIANT_TYPE_INT64)) {
		*out = (st64) g_variant_get_int64 (v);
	} else if (g_variant_is_of_type (v, G_VARIANT_TYPE_INT32)) {
		*out = (st64) g_variant_get_int32 (v);
	} else if (g_variant_is_of_type (v, G_VARIANT_TYPE_UINT64)) {
		*out = (st64) g_variant_get_uint64 (v);
	} else if (g_variant_is_of_type (v, G_VARIANT_TYPE_UINT32)) {
		*out = (st64) g_variant_get_uint32 (v);
	} else {
		ok = false;
	}
	g_variant_unref (v);
	return ok;
}

void r2f_on_compiler_diagnostics(void *user, GVariant *diagnostics) {
	R2FDiagOptions *opts = (R2FDiagOptions *)user;
	bool as_json = opts && opts->json;

	if (!diagnostics || !g_variant_is_container (diagnostics)) {
		return;
	}

	if (as_json) {
		PJ *j = pj_new ();
		pj_a (j);

		GVariantIter it;
		g_variant_iter_init (&it, diagnostics);
		GVariant *elem;
		while ((elem = g_variant_iter_next_value (&it))) {
			if (!g_variant_is_of_type (elem, G_VARIANT_TYPE_VARDICT) &&
					!g_variant_is_of_type (elem, G_VARIANT_TYPE_DICTIONARY)) {
				g_variant_unref (elem);
				continue;
			}
			pj_o (j);
			const char *category = variant_get_str (elem, "category");
			if (category) {
				pj_ks (j, "category", category);
			}
			st64 code;
			if (variant_get_int (elem, "code", &code)) {
				pj_kN (j, "code", code);
			}
			const char *text = variant_get_str (elem, "text");
			if (text) {
				pj_ks (j, "text", text);
			}
			GVariant *file = g_variant_lookup_value (elem, "file", NULL);
			if (file) {
				pj_ko (j, "file");
				const char *path = variant_get_str (file, "path");
				if (path) {
					pj_ks (j, "path", path);
				}
				st64 line, character;
				if (variant_get_int (file, "line", &line)) {
					if (line >= 0) {
						line++; pj_kN (j, "line", line);
					}
				}
				if (variant_get_int (file, "character", &character)) {
					pj_kN (j, "character", character);
				}
				pj_end (j);
				g_variant_unref (file);
			}
			pj_end (j);
			g_variant_unref (elem);
		}

		pj_end (j);
		char *out = pj_drain (j);
		if (out) {
			char *pretty = r_print_json_indent (out, true, "  ", NULL);
			if (pretty) {
				eprintf ("%s\n", pretty);
				free (pretty);
			} else {
				eprintf ("%s\n", out);
			}
			free (out);
		}
		return;
	}

	// Human logs
	GVariantIter it;
	g_variant_iter_init (&it, diagnostics);
	GVariant *elem;
	while ((elem = g_variant_iter_next_value (&it))) {
		if (!g_variant_is_of_type (elem, G_VARIANT_TYPE_VARDICT) &&
				!g_variant_is_of_type (elem, G_VARIANT_TYPE_DICTIONARY)) {
			g_variant_unref (elem);
			continue;
		}
		const char *category = variant_get_str (elem, "category");
		const char *text = variant_get_str (elem, "text");
		GVariant *file = g_variant_lookup_value (elem, "file", NULL);
		const char *path = NULL;
		st64 line = -1, character = -1;
		if (file) {
			path = variant_get_str (file, "path");
			if (variant_get_int (file, "line", &line)) {
				if (line >= 0) {
					line++;
				}
			}
			variant_get_int (file, "character", &character);
			g_variant_unref (file);
		}
		if (!category) {
			category = "info";
		}
		GString *msg = g_string_new (NULL);
		if (path) {
			g_string_append_printf (msg, "%s", path);
			if (line >= 0) {
				g_string_append_printf (msg, ":%d", (int)line);
				if (character >= 0) {
					g_string_append_printf (msg, ":%d", (int)character);
				}
			}
			g_string_append (msg, ": ");
		}
		if (text) {
			g_string_append (msg, text);
		}
		if (!g_strcmp0 (category, "error")) {
			R_LOG_ERROR ("%s", msg->str);
		} else if (!g_strcmp0 (category, "warning")) {
			R_LOG_WARN ("%s", msg->str);
		} else {
			R_LOG_INFO ("%s", msg->str);
		}
		g_string_free (msg, TRUE);
		g_variant_unref (elem);
	}
}
