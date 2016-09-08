#ifndef __CYLANG_H__
#define __CYLANG_H__

#include "frida-core.h"

#define CYLANG_COMPILER_ERROR cylang_compiler_error_quark ()

G_BEGIN_DECLS

enum {
	CYLANG_COMPILER_ERROR_SYNTAX
};

char *cylang_compile(const char *code, GError **error);

GQuark cylang_compiler_error_quark(void);

G_END_DECLS

#endif
