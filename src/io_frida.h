/* radare2 - MIT - Copyright 2016-2026 - pancake, oleavr, mrmacete, murphy */

#ifndef R2FRIDA_IO_FRIDA_H
#define R2FRIDA_IO_FRIDA_H

#include <r_core.h>
#include <r_io.h>
#include "frida-core.h"

#if R2_VERSION_NUMBER < 60000
#error r2frida requires radare2 6.x or newer
#endif

typedef struct {
	const char *cmd_string;
	ut64 serial;
	JsonObject *_cmd_json;
} RFPendingCmd;

typedef struct {
	FridaService *service;
	gulong handler;
	char **scnames;
	int scnames_len;
	bool target_compat32;
	GRegex *match_regex;
	GRegex *filter_regex;
	guint pid_filter;
	guint64 tid_filter;
	bool has_pid_filter;
	bool has_tid_filter;
	GHashTable *pending;
	bool reading;
	bool read_pending;
} R2FSystraceState;

typedef struct r_io_frida_t {
	FridaDevice *device;
	FridaSession *session;
	FridaScript *script;
	GCancellable *cancellable;

	guint pid;
	GMutex lock;
	GCond cond;
	bool suspended;
	volatile bool suspended2;
	RList *stopped_tids;
	int in_callback;
	bool cmdqueue_pending;
	volatile bool detached;
	volatile FridaSessionDetachReason detach_reason;
	FridaCrash *crash;
	volatile bool received_reply;
	JsonObject *reply_stanza;
	GBytes *reply_bytes;
	RCore *r2core;
	RFPendingCmd *pending_cmd;
	char *crash_report;
	RIO *io;
	RSocket *s;
	gulong onmsg_handler;
	gulong ondtc_handler;
	FridaDeviceManager *device_manager;
	R2FSystraceState systrace;
	RStrBuf *sb;
	bool inputmode;
	bool sysret;
} RIOFrida;

R_IPI void r2f_systrace_init(RIOFrida *rf);
R_IPI void r2f_systrace_config_init(RIOFrida *rf);
R_IPI void r2f_systrace_config_fini(RIOFrida *rf);
R_IPI void r2f_systrace_fini(RIOFrida *rf);
R_IPI char *r2f_systrace_list(RIOFrida *rf);
R_IPI void on_systrace_message(FridaService *service, GVariant *message, gpointer user_data);

#endif
