/* radare2 - MIT - Copyright 2016 - pancake */

#include <r_io.h>
#include <r_lib.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include "frida-core.h"

typedef struct {
	FridaDevice *device;
	FridaSession *session;
	FridaDeviceManager *manager;
} RIOFrida;

#define RIOFRIDA_DEV(x) (((RIOFrida*)x->data)->device)
#define RIOFRIDA_SESSION(x) (((RIOFrida*)x->data)->session)

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	/* TODO: talk with child */
	return -1;
}

static bool __resize(RIO *io, RIODesc *fd, ut64 count) {
	return false;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	/* TODO: wait for message from client */
	memset (buf, 0xff, count);
	return count;
}

static int __close(RIODesc *fd) {
	RIOFrida *rf;
	if (!fd || !fd->data) {
		return -1;
	}
	rf = fd->data;
	free (fd->data);
	fd->data = NULL;
	fd->state = R_IO_DESC_TYPE_CLOSED;
	return 0;
}

static ut64 __lseek(RIO* io, RIODesc *fd, ut64 offset, int whence) {
	ut64 r_offset = offset;
	if (!fd || !fd->data) {
		return offset;
	}
	switch (whence) {
	case SEEK_SET:
		r_offset = offset;
		break;
	case SEEK_CUR:
		r_offset += (st64)offset;
		break;
	case SEEK_END:
		r_offset = UT64_MAX;
		break;
	}
	return r_offset;
}

static bool __check(RIO *io, const char *pathname, bool many) {
	return (!strncmp (pathname, "frida://", 8));
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	frida_init (); // TODO: avoid double initialization
	if (__check (io, pathname, 0)) {
		GError *error = NULL;
		int pid = atoi (pathname + 8);
		FridaDeviceList *devices;
		RIOFrida *rf = R_NEW0 (RIOFrida);
		if (!rf) return NULL;
		rf->manager = frida_device_manager_new ();
		devices = frida_device_manager_enumerate_devices_sync (rf->manager, &error);
		if (error != NULL) {
			// TODO: free rf->manager
			eprintf ("Cannot enumerate frida devices\n");
			frida_device_manager_close_sync (rf->manager);
			free (rf);
			return NULL;
		}
		int i, num_devices = frida_device_list_size (devices);
		if (num_devices < 1) {
			eprintf ("Cannot find any device to attach\n");
			frida_device_manager_close_sync (rf->manager);
			free (rf);
			return NULL;
		}
		for (i = 0; i < num_devices ; i++) {
			FridaDevice *device = frida_device_list_get (devices, i);
			eprintf ("FridaDevice: %s\n", frida_device_get_name (device));
			if (frida_device_get_dtype (device) == FRIDA_DEVICE_TYPE_LOCAL) {
				rf->device = g_object_ref (device);
			}
			g_object_unref (device);
		}
		if (!rf->device) {
			eprintf ("Cannot find any device to attach\n");
			return NULL;
		}
		frida_device_attach_sync (rf->device, pid, &error);
		if (error) {
			frida_device_manager_close_sync (rf->manager);
			free (rf);
			return NULL;
		}
#if 0
    script = frida_session_create_script_sync (session, "example",
        "Interceptor.attach(Module.findExportByName(null, \"open\"), {\n"
        "  onEnter: function (args) {\n"
        "    console.log(\"[*] open(\\\"\" + Memory.readUtf8String(args[0]) + \"\\\")\");\n"
        "  }\n"
        "});\n"
        "Interceptor.attach(Module.findExportByName(null, \"close\"), {\n"
        "  onEnter: function (args) {\n"
        "    console.log(\"[*] close(\" + args[0].toInt32() + \")\");\n"
        "  }\n"
        "});",
        &error);
    g_assert (error == NULL);

    g_signal_connect (script, "message", G_CALLBACK (on_message), NULL);

    frida_script_load_sync (script, &error);
    g_assert (error == NULL);

    g_print ("[*] Script loaded\n");

    if (g_main_loop_is_running (loop))
      g_main_loop_run (loop);

    g_print ("[*] Stopped\n");

    frida_script_unload_sync (script, NULL);
    frida_unref (script);
    g_print ("[*] Unloaded\n");

    frida_session_detach_sync (session);
    frida_unref (session);
    g_print ("[*] Detached\n");
  }
  else
  {
    g_printerr ("Failed to attach: %s\n", error->message);
    g_error_free (error);
  }

  frida_unref (local_device);

  frida_device_manager_close_sync (manager);
  frida_unref (manager);
  g_print ("[*] Closed\n");

  g_main_loop_unref (loop);
#endif
		RETURN_IO_DESC_NEW (&r_io_plugin_malloc,
			-1, pathname, rw, mode, rf);
	}
	return NULL;
}

RIOPlugin r_io_plugin_frida = {
	.name = "frida",
	.desc = "frida:// io plugin",
	.license = "LGPL3",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __check,
	.lseek = __lseek,
	.write = __write,
	.resize = __resize,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_frida,
	.version = R2_VERSION
};
#endif
