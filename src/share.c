
/* Handle sharing of our own files */

#include "gnutella.h"

#include "interface.h"

guint32 files_scanned = 0;
guint32 bytes_scanned = 0;

GSList *extensions = NULL;
GSList *shared_dirs = NULL;

gchar stmp_1[4096];
gchar stmp_2[4096];

guint32 monitor_items = 0;

/* ------------------------------------------------------------------------------------------------ */

void share_init(void)
{
	share_scan();
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

void share_scan(void)
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

/* vi: set ts=3: */

