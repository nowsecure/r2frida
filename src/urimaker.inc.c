


static char *choose_action(RIOFrida *rf) {
	RList *items = r_list_newf (free);
	r_list_append (items, strdup ("help"));
	r_list_append (items, strdup ("devices"));
	r_list_append (items, strdup ("attach"));
	r_list_append (items, strdup ("spawn"));
	r_list_append (items, strdup ("launch"));
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
	r_list_append (items, strdup ("Weather"));
	r_list_append (items, strdup ("Notes"));
	gint i;
	GError *error = NULL;

	GCancellable *cancellable = NULL;
	FridaApplicationList *list = frida_device_enumerate_applications_sync (rf->device, NULL, cancellable, &error);
	if (error != NULL) {
		return NULL;
	}
	gint num_applications = frida_application_list_size (list);
	for (i = 0; i != num_applications; i++) {
		FridaApplication *application = frida_application_list_get (list, i);
		guint pid = frida_application_get_pid (application);
		const gchar *name = frida_application_get_name (application);
		const gchar *iden = frida_application_get_identifier (application);
		r_list_append (items, r_str_newf ("%d %s (%s)", pid, name, iden));
		g_object_unref (application); /* borrow it */
	}
	g_clear_error (&error);
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
			R_LOG_ERROR ("%s", error->message);
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
	char *device = choose_device (rf);
	if (device) {
		GError *error = NULL;
		rf->device = get_device_manager (rf->device_manager, device, NULL, &error);
	} else {
		goto repeat;
	}
	char *target = choose_target (rf);
	if (!target) {
		r_cons_clear00 ();
		r_cons_printf ("Nope");
		r_cons_any_key ("");
		goto repeat;
	}
	if (!strcmp (target, "apps")) {
		choose_app (rf);
		goto repeat;
	}
	if (!strcmp (target, "pids")) {
		choose_pid (rf);
		goto repeat;
	}
	char *res = r_str_newf ("?");
	free (action);
	return res;
}

