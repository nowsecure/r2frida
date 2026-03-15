/* radare2 - MIT - Copyright 2026 - pancake, oleavr */

#ifndef R2FRIDA_SYSTRACE_H
#define R2FRIDA_SYSTRACE_H

#include "io_frida.h"

void r2f_systrace_init(RIOFrida *rf);
void r2f_systrace_configure(RIOFrida *rf, bool enabled, const char *match);
void r2f_systrace_fini(RIOFrida *rf);
void on_systrace_message(FridaService *service, GVariant *message, gpointer user_data);

#endif
