/* r2frida - MIT - Copyright 2026 - pancake */

// Glue used when r2frida is statically linked inside libr_core (see r2plugin/README.md).
// io_frida.c depends on r_core, so it can't live in libr_io; instead this core
// plugin registers the frida:// io plugin when the core is initialized.

#include <r_core.h>

extern RIOPlugin r_io_plugin_frida;

static bool r2frida_init(RCorePluginSession *cps) {
	r_libstore_add (cps->core->io->libstore, &r_io_plugin_frida);
	return true;
}

RCorePlugin r_core_plugin_r2frida = {
	.meta = {
		.name = "r2frida",
		.desc = "Register the frida:// io plugin",
		.author = "pancake",
		.license = "MIT",
	},
	.init = r2frida_init,
};
