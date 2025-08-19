// Shared Frida compiler diagnostics handling for r2frida
#ifndef R2FRIDA_DIAGNOSTICS_H
#define R2FRIDA_DIAGNOSTICS_H

#include <stdbool.h>
#include "frida-core.h"

typedef struct {
    bool json; // when true, emit JSON array to stderr; otherwise log human-readable
} R2FDiagOptions;

void r2f_on_compiler_diagnostics(void *user, GVariant *diagnostics);

#endif // R2FRIDA_DIAGNOSTICS_H

