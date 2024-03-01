


static char *choose_action(RIOFrida *rf) {
	RList *items = r_list_newf (free);
	r_list_append (items, strdup ("help"));
	r_list_append (items, strdup ("devices"));
	r_list_append (items, strdup ("attach"));
	r_list_append (items, strdup ("spawn"));
	r_list_append (items, strdup ("launch"));
	r_list_append (items, strdup ("system"));
	char *res = r_cons_hud (items, "[r2frida] Action:");
	r_list_free (items);
	return res;
}

static char *choose_device(RIOFrida *rf) {
	RList *items = r_list_newf (free);
	r_list_append (items, strdup ("local"));
	r_list_append (items, strdup ("usb"));
	r_list_append (items, strdup ("tcp"));
	char *res = r_cons_hud (items, "[r2frida] Device:");
	r_list_free (items);
	return res;
}

static char *choose_target(RIOFrida *rf) {
	RList *items = r_list_newf (free);
	r_list_append (items, strdup ("cancel"));
	r_list_append (items, strdup ("apps"));
	r_list_append (items, strdup ("pids"));
	r_list_append (items, strdup ("file"));
	char *res = r_cons_hud (items, "[r2frida] Target:");
	r_list_free (items);
	return res;
}

static char *choose_app(RIOFrida *rf) {
	RList *items = r_list_newf (free);
	gint i;
	GError *error = NULL;

	GCancellable *cancellable = NULL;
	FridaApplicationList *list = frida_device_enumerate_applications_sync (rf->device, NULL, cancellable, &error);
	if (error != NULL) {
		r_cons_any_key ("ERROR: Cannot list applications");
		return NULL;
	}
	g_clear_error (&error);
	gint num_applications = frida_application_list_size (list);
	if (num_applications == 0) {
		r_cons_any_key ("ERROR: No applications found");
		return NULL;
	}
	for (i = 0; i != num_applications; i++) {
		FridaApplication *application = frida_application_list_get (list, i);
		guint pid = frida_application_get_pid (application);
		const gchar *name = frida_application_get_name (application);
		const gchar *iden = frida_application_get_identifier (application);
		// remove () from app name and trim it down to something reasonable
		char *fname = r_str_ndup (name, 32);
		r_str_replace_char (fname, '(', '[');
		r_str_replace_char (fname, ')', ']');
		r_list_append (items, r_str_newf ("%d %s (%s)", pid, fname, iden));
		free (fname);
		g_object_unref (application); /* borrow it */
	}
	g_clear_object (&list);

	char *res = r_cons_hud (items, "[r2frida] Apps:");
	r_list_free (items);
	return res;
}

static char *choose_pid(RIOFrida *rf) {
	gint i;
	GError *error = NULL;
	GCancellable *cancellable = NULL;

	FridaProcessList *list = frida_device_enumerate_processes_sync (rf->device, NULL, cancellable, &error);
	if (error) {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			char *msg = r_str_newf ("ERROR: %s", error->message);
			r_cons_any_key (msg);
			free (msg);
		}
		return NULL;
	}
	gint num_processes = frida_process_list_size (list);

	RList *items = r_list_newf (free);
	for (i = 0; i != num_processes; i++) {
		FridaProcess *process = frida_process_list_get (list, i);
		gint pid = frida_process_get_pid (process);
		const gchar *name = frida_process_get_name (process);
		r_list_append (items, r_str_newf ("%d %s", pid, name));
		g_object_unref (process); /* borrow it */
	}
	g_clear_error (&error);
	g_clear_object (&list);

	char *res = r_cons_hud (items, "[r2frida] Process:");
	r_list_free (items);
	return res;
}

static char *construct_uri(RIOFrida *rf) {
repeat:;
	char *action = choose_action (rf);
	if (!action) {
		return NULL;
	}
	if (!strcmp (action, "help")) {
		r_cons_clear00 ();
		r_cons_printf ("%s\n", helpmsg);
		r_cons_any_key ("");
		goto repeat;
	}
	if (!strcmp (action, "devices")) {
		// select device
		r_cons_clear00 ();
		dumpDevices (rf, NULL);
		r_cons_any_key ("");
		goto repeat;
	}
	if (!strcmp (action, "system")) {
		return strdup ("0");
	}
	if (!strcmp (action, "attach") || !strcmp (action, "spawn") || !strcmp (action, "launch")) {
		// valid action, move forward
	} else {
		goto repeat;
	}
repeat_device:;
	char *device = choose_device (rf);
	if (device) {
		GError *error = NULL;
		rf->device = get_device_manager (rf->device_manager, device, NULL, &error);
		if (!rf->device) {
			r_cons_any_key ("Invalid device");
			goto repeat_device;
		}
	} else {
		goto repeat;
	}
	char *pid = NULL;
	char *app = NULL;
	char *fil = NULL;
	char *target = choose_target (rf);
	if (!target) {
		r_cons_clear00 ();
		r_cons_any_key ("Nope");
		goto repeat;
	}
	if (!strcmp (target, "apps")) {
		app = choose_app (rf);
		if (R_STR_ISEMPTY (app)) {
			r_cons_any_key ("No app selected");
			goto repeat;
		}
		char *sp = strchr (app, '(');
		if (sp) {
			r_str_cpy (app, sp + 1);
			if (*app) {
				// assume last char is ')'. because bundle id can also contain ')'
				app[strlen (app) - 1] = 0;
			}
		}
	} else if (!strcmp (target, "pids")) {
		pid = choose_pid (rf);
		if (R_STR_ISEMPTY (pid)) {
			r_cons_any_key ("No pid selected");
			goto repeat;
		}
		char *sp = strchr (pid, ' ');
		if (sp) {
			*sp = 0;
		}
	} else if (!strcmp (target, "file")) {
		fil = r_cons_hud_file ("");
	} else {
		goto repeat;
	}
	if (!strcmp (device, "local")) {
		char *res = r_str_newf ("%s", fil);
		free (action);
		return res;
	}
	char *res = r_str_newf ("%s/%s//%s", action, device, app? app: pid);
	free (action);
	return res;
}

