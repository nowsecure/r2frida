static char *choose_action(RIOFrida *rf) {
	RList *items = r_list_newf (free);
	r_list_append (items, strdup ("help"));
	r_list_append (items, strdup ("list"));
	r_list_append (items, strdup ("attach"));
	r_list_append (items, strdup ("apps"));
	r_list_append (items, strdup ("spawn"));
	r_list_append (items, strdup ("launch"));
	char *res = r_cons_hud (items, "Select action:");
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
	if (!strcmp (action, "list")) {
		r_cons_clear00 ();
		dumpDevices (rf, NULL);
		r_cons_any_key ("");
		goto repeat;
	}
	char *res = r_str_newf ("?");
	free (action);
	return res;
}

