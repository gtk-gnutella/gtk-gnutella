
/* Handle searches */

#include "gnutella.h"

#include "interface.h"

#define MAX_EXTENSIONS	128

guint32 files_scanned = 0;
guint32 bytes_scanned = 0;

GSList *extensions = NULL;
GSList *shared_dirs = NULL;

gchar stmp_1[4096];
gchar stmp_2[4096];

guchar last_muid[16];	/* muid of our last search */

guint32 monitor_items = 0;

guint32 items_found = 0;

struct results_set
{
	guchar guid[16];
	guint32 num_recs;
	guint32 ip;
	guint16 port;
	guint32 speed;

	GSList *records;
};

struct record
{
	struct results_set *results_set;
	gchar *name;
	guint32 size;
	guint32 index;
};

GSList *r_sets = NULL;

void clear_search_results(void);

/* ------------------------------------------------------------------------------------------------ */

void search_init(void)
{
	search_scan();
}

/* Get the file extensions to scan */

void parse_extensions(gchar *str)
{
	gchar ** exts = g_strsplit(str, ";", 0);
	gchar *x, *s;
	guint i, e;
	GSList *l;

	if (extensions)
	{
		l = extensions;
		while (l) { g_free(l->data); l = l->next; }
		g_slist_free(extensions);
		extensions = NULL;
	}

	e = i = 0;

	while (exts[i])
	{
		s = exts[i];
		while (*s == ' ' || *s == '\t' || *s == '.' || *s == '*' || *s == '?') s++;
		if (*s)
		{
			x = s + strlen(s);
			while (--x > s && (*x == ' ' || *x == '\t' || *x == '*' || *x == '?')) *x = 0;
			if (*s) extensions = g_slist_append(extensions, g_strdup(s));
		}
		i++;
	}

	g_strfreev(exts);
}

/* Shared dirs */

void shared_dirs_parse(gchar *str)
{
	gchar ** dirs = g_strsplit(str, ":", 0);
	guint i;

	GSList *l;

	if (shared_dirs)
	{
		l = shared_dirs;
		while (l) { g_free(l->data); l = l->next; }
		g_slist_free(shared_dirs);
		shared_dirs = NULL;
	}

	i = 0;

	while (dirs[i])
	{
		if (is_directory(dirs[i])) shared_dirs = g_slist_append(shared_dirs, g_strdup(dirs[i]));
		i++;
	}

	g_strfreev(dirs);
}

void shared_dir_add(gchar *path)
{
	if (!is_directory(path)) return;

	shared_dirs = g_slist_append(shared_dirs, g_strdup(path));

	gui_update_shared_dirs();
}

void recurse_scan(gchar *dir)
{
}

void search_scan(void)
{
	GSList *l;

	files_scanned = 0;
	bytes_scanned = 0;

	for (l = shared_dirs; l; l = l->next) recurse_scan((gchar *) l->data);
}

/* Searches requests (from others nodes) */

void search_request(struct gnutella_node *n)
{
	global_searches++;

	if (monitor_enabled)	/* Update the search monitor */
	{
		gchar *titles[1];

		gtk_clist_freeze(GTK_CLIST(clist_monitor));

		if (monitor_items < monitor_max_items) monitor_items++;
		else gtk_clist_remove(GTK_CLIST(clist_monitor), GTK_CLIST(clist_monitor)->rows - 1);

		titles[0] = n->data + 2;

		gtk_clist_prepend(GTK_CLIST(clist_monitor), titles);

		gtk_clist_set_selectable (GTK_CLIST(clist_monitor), 0, FALSE);

		gtk_clist_thaw(GTK_CLIST(clist_monitor));
	}

	/* TODO find all our files that match the request, and send the list to the requester */

}

/* Sends a search request */

void new_search(guint16 speed, gchar *query)
{
	struct  gnutella_msg_search *m;
	guint32 size;

	size = sizeof(struct gnutella_msg_search) + strlen(query) + 1;

	m = (struct gnutella_msg_search *) g_malloc(size);

	message_set_muid(&(m->header));

	memcpy(last_muid, m->header.muid, 16); 	/* Register the last search muid */

	m->header.function = GTA_MSG_SEARCH;
	m->header.ttl = my_ttl;
	m->header.hops = 0;

	WRITE_GUINT32_LE(size - sizeof(struct gnutella_header), m->header.size);

	WRITE_GUINT16_LE(minimum_speed, m->search.speed);

	strcpy(m->search.query, query);

	message_add(m->header.muid, GTA_MSG_SEARCH, NULL);

	gtk_entry_set_text(GTK_ENTRY(entry_search), "");
	clear_search_results();

	sendto_all((guchar *) m, NULL, size);

	g_free(m);
}

/* Searches results (from others nodes) */

void clear_search_results(void)
{
	GSList *l, *m;

	items_found = 0;

	gtk_widget_set_sensitive(button_search_download, FALSE);
	gtk_clist_clear(GTK_CLIST(clist_search_results));

	gui_update_items_found();

	for (l = r_sets; l; l = l->next)
	{
		for (m = ((struct results_set *) l->data)->records; m; m = m->next)
		{
			g_free(((struct record *) m->data)->name);
			g_free(m->data);
		}

		g_slist_free(((struct results_set *) l->data)->records);

		g_free(l->data);
	}

	g_slist_free(r_sets);

	r_sets = NULL;
}

gint search_compare(struct record *r1, struct record *r2)
{
	switch (search_results_sort_col)
	{
		case 0: return strcmp(r1->name, r2->name);
		case 1: return r1->size - r2->size;
		case 2: return r1->results_set->speed - r2->results_set->speed;
		case 3: return r1->results_set->ip - r2->results_set->ip;
	}
	return 0;
}

void search_results(struct gnutella_node *n)
{
	struct gnutella_search_results *r;
	struct results_set *rs;
	struct record *rc;
	gchar *e, *s, *fname;
	guint32 row, nr, size, index;
	GSList *l;
	gchar *titles[4];

	if (memcmp(n->header.muid, last_muid, 16)) return; /* Show only results for our last search */

	r = (struct gnutella_search_results *) n->data;

	rs = (struct results_set *) g_malloc0(sizeof(struct results_set));

	rs->num_recs = (guint8) r->num_recs;
	READ_GUINT32_BE(r->host_ip, rs->ip);
	READ_GUINT16_LE(r->host_port, rs->port);
	READ_GUINT32_LE(r->host_speed, rs->speed);

	s  = r->records;					/* Start of the records */
	e  = s + n->size - 16 - 11;	/* End of the records */
	nr = 0;

	while (s < e && nr < rs->num_recs)
	{
		READ_GUINT32_LE(s, index); s += 4;
		READ_GUINT32_LE(s, size);  s += 4;
		fname = s;

		while (s < e && *s) s++;

		if (s >= e)
		{
/*			fprintf(stderr, "Node %s: %u records found in set (node said %u records)\n", node_ip(n), nr, rs->num_recs); */
			return;
		}

		if (s[1])
		{
/*			fprintf(stderr, "Node %s: Record %u is not double-NULL terminated !\n", node_ip(n), nr); */
			return;
		}

		/* Okay, one more record */

		nr++;

		rc = (struct record *) g_malloc0(sizeof(struct record));

		rc->index = index;
		rc->size  = size;
		rc->name  = g_strdup(fname);

		rc->results_set = rs;

		rs->records = g_slist_prepend(rs->records, (gpointer) rc);

		s += 2;	/* Skips the two null bytes at the end */
	}

	if (s < e)
	{
/*		fprintf(stderr, "Node %s: %u records found in set, but %u bytes remains after the records !\n", node_ip(n), nr, e - s); */
		return;
	}
	else if (s > e)
	{
/*		fprintf(stderr, "Node %s: %u records found in set, but last record exceeded the struct by %u bytes !\n", node_ip(n), nr, s - e); */
		return;
	}

	/* We now have the guid of the node */

	memcpy(rs->guid, s, 16);

	/* The result set is ok */

	r_sets = g_slist_prepend(r_sets, (gpointer) rs);	/* Adds the set to the list */

	/* Update the GUI... */

	gtk_clist_freeze(GTK_CLIST(clist_search_results));

	for (l = rs->records; l; l = l->next)
	{
		rc = (struct record *) l->data;

		titles[0] = rc->name;
		titles[1] = short_size(rc->size);
		g_snprintf(stmp_2, sizeof(stmp_2), "%u", rs->speed); titles[2] = stmp_2;
		titles[3] = ip_port_to_gchar(rs->ip, rs->port);

		if (!search_results_sort)
		{
			/* Just appends the result */

			row = gtk_clist_append(GTK_CLIST(clist_search_results), titles);
		}
		else
		{
			/* gtk_clist_set_auto_sort() can't work for row data based sorts ! Too bad. */
			/* So we need to find the place to put the result by ourselves. */

			GList *work;
	  
			row = 0;

			work = GTK_CLIST(clist_search_results)->row_list;

			if (search_results_sort_order > 0)
			{
				while (row < GTK_CLIST(clist_search_results)->rows && search_compare(rc, (struct record *) GTK_CLIST_ROW(work)->data) > 0)
				{
					row++;
					work = work->next;
				}
			}
			else
			{
				while (row < GTK_CLIST(clist_search_results)->rows && search_compare(rc, (struct record *) GTK_CLIST_ROW(work)->data) < 0)
				{
					row++;
					work = work->next;
				}
			}

			gtk_clist_insert(GTK_CLIST(clist_search_results), row, titles);
		}

		gtk_clist_set_row_data(GTK_CLIST(clist_search_results), row, (gpointer) rc);

		items_found++;
	}

	gtk_clist_thaw(GTK_CLIST(clist_search_results));

	gui_update_items_found();
}

/* ------------------------------------------------------------------------------------------------ */

void search_download_files(void)
{
	/* Download the selected files */

	struct results_set *rs;
	struct record *rc;
	GList *l;

	gtk_notebook_set_page(GTK_NOTEBOOK(notebook_main), 2);
	gtk_clist_select_row(GTK_CLIST(clist_menu), 2, 0);

	for (l = GTK_CLIST(clist_search_results)->selection; l; l = l->next)
	{
		rc = (struct record *) gtk_clist_get_row_data(GTK_CLIST(clist_search_results), (gint) l->data);
		rs = rc->results_set;
		download_new(rc->name, rc->size, rc->index, rs->ip, rs->port, rs->guid);
	}

	gtk_clist_unselect_all(GTK_CLIST(clist_search_results));
}

/* ------------------------------------------------------------------------------------------------ */

gint search_results_compare_size(GtkCList *clist, gconstpointer ptr1, gconstpointer ptr2)
{
	return (((struct record *) ((GtkCListRow *) ptr1)->data)->size - ((struct record *) ((GtkCListRow *) ptr2)->data)->size);
}

gint search_results_compare_speed(GtkCList *clist, gconstpointer ptr1, gconstpointer ptr2)
{
	return (((struct record *) ((GtkCListRow *) ptr1)->data)->results_set->speed - ((struct record *) ((GtkCListRow *) ptr2)->data)->results_set->speed);
}

gint search_results_compare_ip(GtkCList *clist, gconstpointer ptr1, gconstpointer ptr2)
{
	return (((struct record *) ((GtkCListRow *) ptr1)->data)->results_set->ip - ((struct record *) ((GtkCListRow *) ptr2)->data)->results_set->ip);
}

/* vi: set ts=3: */

