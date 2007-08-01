/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
 *
 *----------------------------------------------------------------------
 * This file is part of gtk-gnutella.
 *
 *  gtk-gnutella is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  gtk-gnutella is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with gtk-gnutella; if not, write to the Free Software
 *  Foundation, Inc.:
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

#include "gtk/gui.h"

RCSID("$Id$")

#include "downloads_cb.h"

#include "gtk/columns.h"
#include "gtk/downloads.h"
#include "gtk/downloads_common.h"
#include "gtk/misc.h"
#include "gtk/notebooks.h"
#include "gtk/settings.h"
#include "gtk/statusbar.h"

#include "if/core/pproxy.h"
#include "if/core/bsched.h"
#include "if/bridge/ui2c.h"

#include "lib/atoms.h"
#include "lib/glib-missing.h"
#include "lib/tm.h"
#include "lib/utf8.h"
#include "lib/override.h"	/* Must be the last header included */

static gchar tmpstr[4096];
static GHashTable *parents;			/**< table of parent download iterators */
static GHashTable *parents_queue;	/**< table of parent queued dl iterators */

/*
 * parents_gui_time
 *
 * I did not know how to attach meta information to the parent GUI structures,
 * so I created this hash table to record the last time we update the parent
 * information in the GUI, to avoid doing too costly lookups in the ctree when
 * the information is already accurate, with a granularity of a second.
 *
 *		--RAM, 03/01/2004.
 */
static GHashTable *parents_gui_time;	/**< Time at which parent was updated */

/*
 * parents_children
 * parents_queue_children
 *
 * Keeps track of the amount of children a parent has, to avoid costly
 * calls to count_node_children.
 */
static GHashTable *parents_children;
static GHashTable *parents_queue_children;

static GtkCTree *ctree_downloads;
static GtkCTree *ctree_queue;
static GtkNotebook *notebook;

static gboolean ctree_downloads_frozen = FALSE;
static gboolean ctree_queue_frozen = FALSE;

#define DL_GUI_TREE_SPACE	5	/**< Space between a child node and a parent */

/***
 *** Private functions
 ***/

/**
 * Add the given tree node to the hashtable.
 * The key is an int ref on the fi_handle for a given download.
 */
static inline void
add_parent_with_fi_handle(GHashTable *ht, gpointer key, GtkCTreeNode *data)
{
	/*
	 * Since we're inserting an integer ref into the hash table, we need
	 * to make it an atom.
	 */

	g_hash_table_insert(ht, key, data);
}

/**
 * Removes the treenode matching the given fi_handle from the hash table
 * and frees the original key used to store it.
 */
static inline void
remove_parent_with_fi_handle(GHashTable *ht, const gnet_fi_t fi_handle)
{
	gpointer key;
	GtkCTreeNode *data = NULL;
	gpointer orig_key;

	key = GUINT_TO_POINTER(fi_handle);

	if (
		g_hash_table_lookup_extended(ht, key,
			(gpointer) &orig_key, (gpointer) &data)
	) {
		g_hash_table_remove(ht, key);
	} else
		g_warning("remove_parent_with_fi_handle:can't find fi in hash table!");

	/*
	 * If we removed a `parent', we must also delete the corresponding
	 * entry in the table tracking the last GUI update time.
	 */

	if (
		ht == parents &&
		g_hash_table_lookup_extended(parents_gui_time, key,
			(gpointer) &orig_key, (gpointer) &data)
	) {
		g_hash_table_remove(parents_gui_time, key);
	}
}


/**
 * @return the tree iterator corresponding to the given key, an atomized
 * fi_handle.
 */
static inline
GtkCTreeNode *find_parent_with_fi_handle(GHashTable *ht, gpointer key)
{
	return g_hash_table_lookup(ht, key);
}

/**
 * Remember when we did the last GUI update of the parent.
 */
static inline void
record_parent_gui_update(gpointer key, time_t when)
{
	gpointer orig_key;
	gpointer data;

	if (
		g_hash_table_lookup_extended(parents_gui_time, key,
			(gpointer) &orig_key, (gpointer) &data)
	)
		g_hash_table_insert(parents_gui_time, orig_key, GINT_TO_POINTER(when));
	else
		g_hash_table_insert(parents_gui_time, key, GINT_TO_POINTER(when));
}

/**
 * @return the last time we updated the GUI of the parent.
 */
static inline time_t
get_last_parent_gui_update(gpointer key)
{
	return (time_t) GPOINTER_TO_INT(g_hash_table_lookup(parents_gui_time, key));
}

/**
 * @return whether the parent of download `d', if any, needs a GUI update.
 */
static inline gboolean
parent_gui_needs_update(struct download *d, time_t now)
{
	gpointer key = GUINT_TO_POINTER(d->file_info->fi_handle);
	gpointer parent = find_parent_with_fi_handle(parents, key);

	if (parent == NULL)
		return FALSE;

	return get_last_parent_gui_update(key) != now;
}

/**
 * Add (arithmetically) `x' to the amount of children of the parent, identified
 * by its fileifo hande.
 *
 * The `ctree' is used to determine whether we're managing a parent from
 * the active downlods or the queue downlaods.
 *
 * @return the new amount of children (use x=0 to get the current count).
 */
static gint
parent_children_add(GtkCTree *ctree, gpointer key, gint x)
{
	GHashTable *ht = NULL;
	gpointer k;
	gpointer v;
	gint cnt;

	if (ctree == ctree_downloads)
		ht = parents_children;
	else if (ctree == ctree_queue)
		ht = parents_queue_children;
	else
		g_error("unknown ctree object");

	/*
	 * If nothing in the table already, we can only add a children.
	 */

	if (!g_hash_table_lookup_extended(ht, key, &k, &v)) {
		g_assert(x >= 0);
		if (x == 0)
			return 0;
		g_hash_table_insert(ht, key, GINT_TO_POINTER(x));
		return x;
	}

	g_assert(GPOINTER_TO_UINT(k) == GPOINTER_TO_UINT(key));

	cnt = GPOINTER_TO_INT(v);

	/*
	 * Update table entry, removing it when the children count reaches 0.
	 */

	if (x != 0) {
		cnt += x;
		g_assert(cnt >= 0);
		if (cnt > 0)
			g_hash_table_insert(ht, k, GINT_TO_POINTER(cnt));
		else
			g_hash_table_remove(ht, k);
	}

	return cnt;
}


/**
 *	Given a GList of GtkCTreeNodes, return a new list pointing to the row data
 *	If unselect is TRUE, unselect all nodes in the list
 *  If children is TRUE, check and strip out header nodes.  Instead of adding
 *  the headers, add all of their children.
 *	List will have to be freed later on.
 *
 * FIXME: Worst case approaches O(n*n) ensuring no duplicate children are added
 * FIXME: There are a lot of glist "appends" in here => unneccesary O(n)
 */
GList *
downloads_gui_collect_ctree_data(GtkCTree *ctree, GList *node_list,
	gboolean unselect, gboolean add_children)
{
	GList *data_list = NULL, *dup_list = NULL;
	struct download *d, *dtemp;
	GtkCTreeNode *node, *parent;
	GtkCTreeRow *row;

	for (; node_list != NULL; node_list = g_list_next(node_list)) {

		if (node_list->data != NULL) {
			d = gtk_ctree_node_get_row_data(ctree, node_list->data);

			if (DL_GUI_IS_HEADER == d) { /* Is a parent */

				parent = GTK_CTREE_NODE(node_list->data);
				row = GTK_CTREE_ROW(parent);
				node = row->children;

				if (add_children) {
					/* Do not add parent, but add all children of parent */
					for (; NULL != node; row = GTK_CTREE_ROW(node),
						node = row->sibling) {
						dtemp = gtk_ctree_node_get_row_data(ctree, node);

						data_list = g_list_append(data_list, dtemp);
						dup_list = g_list_append(dup_list, dtemp);
					}
				} else {
					/* We only want to add one download struct to represent  all
					 * the nodes under this parent node.  We choose the download
					 * struct of the first child.
					 */
					dtemp = gtk_ctree_node_get_row_data(ctree, node);
					data_list = g_list_append(data_list, dtemp);
					dup_list = g_list_append(dup_list, dtemp);
				}
			} else {

				/* Make sure we are not adding a child twice (if the child and
				 * the parent was selected.
				 */
				if (NULL == g_list_find(dup_list, d))
					data_list = g_list_append(data_list, d);
			}
			if (unselect)
				gtk_ctree_unselect(ctree, node_list->data);
		}
	}

	g_list_free(dup_list);
	data_list = g_list_first(data_list);
	return data_list;
}

/**
 *	@return true if any of the active downloads in the same tree as the given
 * 	download are in the specified status.
 */
static gboolean
downloads_gui_any_status(struct download *d, download_status_t status)
{
	gpointer key;
	GtkCTreeNode *node, *parent;
	GtkCTreeRow *row;

	if (!d->file_info)
		return FALSE;

	key = GUINT_TO_POINTER(d->file_info->fi_handle);
	parent = find_parent_with_fi_handle(parents, key);

	if (!parent)
		return FALSE;

	row = GTK_CTREE_ROW(parent);
	node = row->children;

	for (; node != NULL; row = GTK_CTREE_ROW(node), node = row->sibling) {
		struct download *drecord;

		drecord = gtk_ctree_node_get_row_data(ctree_downloads, node);
		if (!drecord || DL_GUI_IS_HEADER == drecord)
			continue;

		if (drecord->status == status)
			return TRUE;
	}

	return FALSE;
}

/**
 *	@return true if all the active downloads in the same tree as the given
 * 	download are aborted (status is GTA_DL_ABORTED or GTA_DL_ERROR).
 */
gboolean
downloads_gui_all_aborted(struct download *d)
{
	struct download *drecord = NULL;
	gpointer key;
	gboolean all_aborted = FALSE;
	GtkCTreeNode *node, *parent;
	GtkCTreeRow *row;

	if (NULL != d->file_info) {

		key = GUINT_TO_POINTER(d->file_info->fi_handle);
		parent = find_parent_with_fi_handle(parents, key);

		if (NULL != parent) {

			all_aborted = TRUE;

			row = GTK_CTREE_ROW(parent);
			node = row->children;

			for (; NULL != node;
				row = GTK_CTREE_ROW(node), node = row->sibling) {

				drecord = gtk_ctree_node_get_row_data(ctree_downloads, node);

				if ((NULL == drecord) || (-1 == GPOINTER_TO_INT(drecord)))
					continue;

				if ((GTA_DL_ABORTED != drecord->status)
					&& (GTA_DL_ERROR != drecord->status)) {
					all_aborted = FALSE;
					break;
				}
			}
		}
	}

	return all_aborted;
}


/**
 * 	Finds parent of given download in the active download tree and changes the
 *  status column to the given string.  Returns true if status is changed.
 */
gboolean
downloads_gui_update_parent_status(struct download *d, time_t now,
	gchar *new_status)
{
	gpointer key;
	gboolean changed = FALSE;

	GdkColor *color;
	GtkCTreeNode *parent;


    if (NULL != d->file_info) {

		key = GUINT_TO_POINTER(d->file_info->fi_handle);
		parent = find_parent_with_fi_handle(parents, key);

		if (NULL != parent) {

			changed = TRUE;
			gtk_ctree_node_set_text(ctree_downloads, parent,
				c_dl_status, new_status);

			if (0 == strcmp(new_status, "Push mode")) {
				color = &(gtk_widget_get_style(GTK_WIDGET(ctree_downloads))
					->fg[GTK_STATE_INSENSITIVE]);

				gtk_ctree_node_set_foreground(ctree_downloads, parent, color);
			}
			record_parent_gui_update(key, now);
		}
	}

	return changed;
}


/* FIXME: instead of this download_gui should pull a listener on
 *        fileinfo status changes, but since the downloads gui
 *        has to be overhauled for better fileinfo integration anyway,
 *        I didn't do this now.
 *     --BLUE, 10/1/2004
 */
#if 0
void gui_update_download_hostcount(struct download *d)
{
	gpointer key;
	GtkCTreeNode *parent;

    if (NULL != d->file_info) {

		key = GUINT_TO_POINTER(d->file_info->fi_handle);
		parent = find_parent_with_fi_handle(parents, key);

		if (NULL != parent) {
            guint32 n;

			n = count_node_children(ctree_downloads, parent);
			gm_snprintf(tmpstr, sizeof(tmpstr),
                "%u hosts", n);

			gtk_ctree_node_set_text(ctree_downloads,  parent,
                c_dl_host, tmpstr);
        }
    }
}
#endif	/* 0 */

/**
 * Initialize local data structures.
 */
void
downloads_gui_init(void)
{
    GtkCList *clist;

	notebook = GTK_NOTEBOOK(gui_main_window_lookup("notebook_main"));
	ctree_downloads = GTK_CTREE(gui_main_window_lookup("ctree_downloads"));
	ctree_queue = GTK_CTREE(gui_main_window_lookup("ctree_downloads_queue"));

	clist = GTK_CLIST(ctree_queue);
    gtk_clist_column_titles_passive(clist);
    gtk_clist_set_column_justification(clist, c_queue_size, GTK_JUSTIFY_RIGHT);
	clist_restore_widths(clist, PROP_DL_QUEUED_COL_WIDTHS);


	clist = GTK_CLIST(ctree_downloads);
    gtk_clist_column_titles_passive(clist);
    gtk_clist_set_column_justification(
        clist, c_dl_size, GTK_JUSTIFY_RIGHT);
    gtk_clist_set_column_justification(
        clist, c_dl_progress, GTK_JUSTIFY_RIGHT);
	clist_restore_widths(clist, PROP_DL_ACTIVE_COL_WIDTHS);

	parents = g_hash_table_new(NULL, NULL);
	parents_queue = g_hash_table_new(NULL, NULL);
	parents_gui_time = g_hash_table_new(NULL, NULL);
	parents_children = g_hash_table_new(NULL, NULL);
	parents_queue_children = g_hash_table_new(NULL, NULL);
}

/**
 * Cleanup local data structures.
 */
void
downloads_gui_shutdown(void)
{
	clist_save_widths(GTK_CLIST(ctree_downloads), PROP_DL_ACTIVE_COL_WIDTHS);
	clist_save_widths(GTK_CLIST(ctree_queue), PROP_DL_QUEUED_COL_WIDTHS);

	g_hash_table_destroy(parents);
	g_hash_table_destroy(parents_queue);
	g_hash_table_destroy(parents_gui_time);
	g_hash_table_destroy(parents_children);
	g_hash_table_destroy(parents_queue_children);
}

#define DL_VISIBLE_MAX \
	MAX(DOWNLOADS_VISIBLE_COLUMNS, DOWNLOAD_QUEUE_VISIBLE_COLUMNS)

/**
 *	Adds a download to the gui.  All parenting (grouping) is done here
 */
void
download_gui_add(struct download *d)
{
	const gchar *UNKNOWN_SIZE_STR = _("no size");
	const gchar *titles[DL_VISIBLE_MAX];
	const gchar *titles_parent[DL_VISIBLE_MAX];
	GtkCTreeNode *new_node, *parent;
	GdkColor *color;
	gchar vendor[256];
	const gchar *file_name, *filename;
	gchar *size, *host, *range, *server, *status, *country;
	struct download *drecord;
	gpointer key;
	gint n;

	g_return_if_fail(d);

	if (DOWNLOAD_IS_VISIBLE(d)) {
		g_warning
			("download_gui_add() called on already visible download '%s' !",
			 d->file_name);
		return;
	}

	/*
	 * When `record_index' is URN_INDEX, the `file_name' is the URN, which
	 * is not something really readable.  Better display the target filename
	 * on disk in that case.
	 *		--RAM, 22/10/2002
	 */

	file_name = guc_file_info_readable_filename(d->file_info);

	concat_strings(vendor, sizeof vendor,
		(d->server->attrs & DLS_A_BANNING) ? "*" : "", download_vendor_str(d),
		(void *) 0);

	color = &(gtk_widget_get_style(GTK_WIDGET(ctree_downloads))
				->fg[GTK_STATE_INSENSITIVE]);

	titles[c_queue_filename] = file_name;
    titles[c_queue_server] = lazy_utf8_to_locale(vendor);
	titles[c_queue_status] = "";

	if (d->file_info->file_size_known)
		titles[c_queue_size] = short_size(d->file_info->size,
									show_metric_units());
	else
		titles[c_queue_size] = UNKNOWN_SIZE_STR;

 	titles[c_queue_host] = guc_download_get_hostname(d);
 	titles[c_queue_loc] = guc_download_get_country(d);

	if (DOWNLOAD_IS_QUEUED(d)) {
		if (NULL != d->file_info) {
			key = GUINT_TO_POINTER(d->file_info->fi_handle);
			parent = find_parent_with_fi_handle(parents_queue, key);
			if (NULL != parent) {
				/* 	There already is a download with that file_info
				 *	we need to figure out if there is a header entry yet
				 */
				drecord = gtk_ctree_node_get_row_data(ctree_queue, parent);

				if (DL_GUI_IS_HEADER != drecord) {	/* not a header entry */
					/* No header entry so we will create one */
					/* Copy the old parents info into a new node */

					filename = guc_file_info_readable_filename
						(drecord->file_info);
					gtk_ctree_node_get_text(ctree_queue, parent,
						c_queue_host, &host);
					gtk_ctree_node_get_text(ctree_queue, parent,
						c_queue_size, &size);
					gtk_ctree_node_get_text(ctree_queue, parent,
						c_queue_server, &server);
					gtk_ctree_node_get_text(ctree_queue, parent,
						c_queue_status, &status);
					gtk_ctree_node_get_text(ctree_queue, parent,
						c_queue_loc, &country);

					titles_parent[c_queue_filename] = filename;
			        titles_parent[c_queue_server] = server;
       				titles_parent[c_queue_status] = status;
					titles_parent[c_queue_size] = "\"";
        			titles_parent[c_queue_host] = host;
        			titles_parent[c_queue_loc] = country;

					new_node = gtk_ctree_insert_node(ctree_queue,
						parent, NULL,
						(gchar **) titles_parent, /* Override const */
						DL_GUI_TREE_SPACE, NULL, NULL, NULL, NULL,
						FALSE, FALSE);

					parent_children_add(ctree_queue, key, 1);

					gtk_ctree_node_set_row_data(ctree_queue, new_node, drecord);

					if (drecord->always_push)
						 gtk_ctree_node_set_foreground(ctree_queue,
							new_node, color);

					/* Clear old values in parent, turn it into a header */
					gtk_ctree_node_set_text(ctree_queue, parent,
						c_queue_filename, filename);
					gtk_ctree_node_set_text(ctree_queue, parent,
						c_queue_size, size);
					gtk_ctree_node_set_text(ctree_queue, parent,
						c_queue_server, "");
					gtk_ctree_node_set_text(ctree_queue, parent,
						c_queue_status, "");
					gtk_ctree_node_set_text(ctree_queue, parent,
						c_queue_loc, "");

					gtk_ctree_node_set_row_data(ctree_queue, parent,
						DL_GUI_IS_HEADER);
				}

				/*
				 * Whether we just created the header node or one existed
				 * already, we proceed the same.  Namely, by adding the current
				 * download `d' into a new child node and then updating the
				 * header entry
				 */

				/*
				 * It's a child node so we suppress some extraneous column
				 * text to make the gui more readable
				 */
				titles[c_queue_size] = "\"";

				new_node = gtk_ctree_insert_node(ctree_queue,
						parent, NULL,
						(gchar **) titles, /* Override const */
						DL_GUI_TREE_SPACE, NULL, NULL, NULL, NULL,
						FALSE, FALSE);

				gtk_ctree_node_set_row_data(ctree_queue, new_node, d);

				if (d->always_push)
					 gtk_ctree_node_set_foreground(ctree_queue,
						new_node, color);

				n = parent_children_add(ctree_queue, key, 1);
				gm_snprintf(tmpstr, sizeof(tmpstr),
					NG_("%u host", "%u hosts", n), n);

				gtk_ctree_node_set_text(ctree_queue, parent,
					c_queue_host, tmpstr);

			} else {
				/*  There are no other downloads with the same file_info
				 *  Add download as normal
				 *
				 *  Later when we remove this from the parents hash_table
				 *  the file_info atom will be destroyed.  We can leave it
				 *  for now.
				 */
				new_node = gtk_ctree_insert_node(ctree_queue,
						NULL, NULL,
						(gchar **) titles, /* Override const */
						DL_GUI_TREE_SPACE, NULL, NULL, NULL, NULL,
						FALSE, FALSE);
				gtk_ctree_node_set_row_data(ctree_queue, new_node, d);
				if (d->always_push)
					 gtk_ctree_node_set_foreground(ctree_queue,
						new_node, color);
				add_parent_with_fi_handle(parents_queue, key, new_node);
			}
		}
	} else {					/* This is an active download */

		titles[c_dl_filename] = file_name;
		titles[c_dl_server] = lazy_utf8_to_locale(vendor);
		titles[c_dl_status] = "";

		if (d->file_info->file_size_known)
			titles[c_dl_size] = short_size(d->file_info->size,
									show_metric_units());
		else
			titles[c_dl_size] = UNKNOWN_SIZE_STR;
		titles[c_dl_range] = "";
        titles[c_dl_host] = guc_download_get_hostname(d);
        titles[c_dl_loc] = guc_download_get_country(d);
        titles[c_dl_progress] = source_progress_to_string(d);

		if (NULL != d->file_info) {
			key = GUINT_TO_POINTER(d->file_info->fi_handle);
			parent = find_parent_with_fi_handle(parents, key);
			if (NULL != parent) {
				/* 	There already is a download with that file_info
				 *	we need to figure out if there is a header entry yet
				 */
				drecord = gtk_ctree_node_get_row_data(ctree_downloads,
					parent);

				if (DL_GUI_IS_HEADER != drecord) {
					/* No header entry so we will create one */
					/* Copy the old parents info into a new node */

					filename = guc_file_info_readable_filename
						(drecord->file_info);
					gtk_ctree_node_get_text(ctree_downloads, parent,
						c_dl_host, &host);
					gtk_ctree_node_get_text(ctree_downloads, parent,
						c_dl_size, &size);
					gtk_ctree_node_get_text(ctree_downloads, parent,
						c_dl_server, &server);
					gtk_ctree_node_get_text(ctree_downloads, parent,
						c_dl_status, &status);
					gtk_ctree_node_get_text(ctree_downloads, parent,
						c_dl_range, &range);
					gtk_ctree_node_get_text(ctree_downloads, parent,
						c_dl_loc, &country);

					titles_parent[c_dl_filename] = filename;
			        titles_parent[c_dl_server] = server;
       				titles_parent[c_dl_status] = status;
					titles_parent[c_dl_size] = "\"";
					titles_parent[c_dl_host] = host;
			        titles_parent[c_dl_loc] = country;
        			titles_parent[c_dl_range] = range;
        			titles_parent[c_dl_progress] = source_progress_to_string(d);

					new_node = gtk_ctree_insert_node(ctree_downloads,
						parent, NULL,
						(gchar **) titles_parent, /* Override const */
						DL_GUI_TREE_SPACE, NULL, NULL, NULL, NULL,
						FALSE, FALSE);

					parent_children_add(ctree_downloads, key, 1);

					gtk_ctree_node_set_row_data(ctree_downloads, new_node,
						(gpointer) drecord);

					if (DOWNLOAD_IS_IN_PUSH_MODE(d))
						 gtk_ctree_node_set_foreground(ctree_downloads,
							new_node, color);

					/* Clear old values in parent, turn it into a header */
					gtk_ctree_node_set_text(ctree_downloads, parent,
						c_dl_filename, filename);
					gtk_ctree_node_set_text(ctree_downloads, parent,
						c_dl_size, size);
					gtk_ctree_node_set_text(ctree_downloads, parent,
						c_dl_server, "");
					gtk_ctree_node_set_text(ctree_downloads, parent,
						c_dl_status, "");
					gtk_ctree_node_set_text(ctree_downloads, parent,
						c_dl_range, "");
					gtk_ctree_node_set_text(ctree_downloads, parent,
						c_dl_loc, "");
					gtk_ctree_node_set_text(ctree_downloads, parent,
						c_dl_progress, download_progress_to_string(d));

					gtk_ctree_node_set_row_data(ctree_downloads, parent,
						DL_GUI_IS_HEADER);
				}

				/*
				 * Whether we just created the header node or one existed
				 * already, we proceed the same.  Namely, by adding the current
				 * download `d' into a new child node and then updating the
				 * header entry
				 */

				/* It's a child node so we suppress some extraneous column
				 * text to make the gui more readable
				 */
				titles[c_dl_size] = "\"";

				new_node = gtk_ctree_insert_node(ctree_downloads,
						parent, NULL,
						(gchar **) titles, /* Override const */
						DL_GUI_TREE_SPACE, NULL, NULL, NULL, NULL,
						FALSE, FALSE);

				gtk_ctree_node_set_row_data(ctree_downloads, new_node,
						(gpointer) d);

				if (DOWNLOAD_IS_IN_PUSH_MODE(d))
					 gtk_ctree_node_set_foreground(ctree_downloads,
						new_node, color);

				n = parent_children_add(ctree_downloads, key, 1);
				gm_snprintf(tmpstr, sizeof(tmpstr),
					NG_("%u host", "%u hosts", n), n);

				gtk_ctree_node_set_text(ctree_downloads, parent,
					c_dl_host, tmpstr);

			} else {
				/*  There are no other downloads with the same file_info
				 *  Add download as normal
				 *
				 *  Later when we remove this from the parents hash_table
				 *  the file_info atom will be destroyed.  We can leave it
				 *  for now.
				 */
				new_node = gtk_ctree_insert_node(ctree_downloads,
						NULL, NULL,
						(gchar **) titles, /* Override const */
						DL_GUI_TREE_SPACE, NULL, NULL, NULL, NULL,
						FALSE, FALSE);
				gtk_ctree_node_set_row_data(ctree_downloads, new_node,
						(gpointer) d);
				if (DOWNLOAD_IS_IN_PUSH_MODE(d))
					 gtk_ctree_node_set_foreground(ctree_downloads,
						new_node, color);
				add_parent_with_fi_handle(parents, key, new_node);
			}
		}
	}

	d->visible = TRUE;
}


void
gui_update_download_server(struct download *d)
{
	GtkCTreeNode *node;

	g_return_if_fail(DL_GUI_IS_HEADER != d);

	download_check(d);
	g_assert(d->status != GTA_DL_QUEUED);
	g_assert(d->server);
	g_assert(download_vendor(d));

	node = gtk_ctree_find_by_row_data(ctree_downloads, NULL, d);
	if (NULL != node) {
		/*
		 * Prefix vendor name with a '*' if they are considered as potentially
		 * banning us and we activated anti-banning features.
		 *		--RAM, 05/07/2003
		 */

		concat_strings(tmpstr, sizeof tmpstr,
			(d->server->attrs & DLS_A_BANNING) ? "*" : "", download_vendor(d),
			(void *) 0);

		gtk_ctree_node_set_text(ctree_downloads, node, c_dl_server,
			lazy_utf8_to_locale(tmpstr));
	}
}

void
gui_update_download_range(struct download *d)
{
	GtkCTreeNode *node;

	g_return_if_fail(DL_GUI_IS_HEADER != d);

	download_check(d);
	g_assert(d->status != GTA_DL_QUEUED);

	node = gtk_ctree_find_by_row_data(ctree_downloads, NULL, d);
	if (node) {
		gtk_ctree_node_set_text(ctree_downloads, node,
			c_dl_range, downloads_gui_range_string(d));
	}
}

/*
 * Update the size of the active download.
 */
void
gui_update_download_size(struct download *d)
{
	GtkCTreeNode *node;

	g_return_if_fail(DL_GUI_IS_HEADER != d);

	download_check(d);
	g_assert(!DOWNLOAD_IS_QUEUED(d));

	if (!d->file_info->file_size_known)
		return;

	gm_snprintf(tmpstr, sizeof tmpstr, "%s",
		short_size(d->size, show_metric_units()));

	node = gtk_ctree_find_by_row_data(ctree_downloads, NULL, (gpointer) d);
	if (NULL != node)
		gtk_ctree_node_set_text(ctree_downloads, node, c_dl_size, tmpstr);
}

void
gui_update_download_host(struct download *d)
{
	GtkCTreeNode *node;

	g_return_if_fail(DL_GUI_IS_HEADER != d);

	download_check(d);
	g_assert(!DOWNLOAD_IS_QUEUED(d));
	g_assert(d->status != GTA_DL_QUEUED);

	node = gtk_ctree_find_by_row_data(ctree_downloads, NULL, (gpointer) d);
	if (NULL != node) {
		gtk_ctree_node_set_text(ctree_downloads, node,
			c_dl_host, guc_download_get_hostname(d));
		gtk_ctree_node_set_text(ctree_downloads, node,
			c_dl_loc, guc_download_get_country(d));
	}
}

void
gui_update_download(struct download *d, gboolean force)
{
	const gchar *a = NULL;
	time_t now = tm_time();
    GdkColor *color;
	GtkCTreeNode *node, *parent;
	struct download *drecord;
	fileinfo_t *fi;
	gpointer key;
	gint active_src, tot_src;
	gboolean copy_status_to_parent = FALSE;
	gint rw;
    gint current_page;
	gboolean looking = TRUE;

	g_return_if_fail(DL_GUI_IS_HEADER != d);

    if (d->last_gui_update == now && !force)
		return;

	/*
	 * Why update if no one's looking?
	 *
	 * We must update some of the download entries even if nobody is
	 * looking because we don't periodically update the GUI for all the
	 * states...
	 */

    current_page = gtk_notebook_get_current_page(notebook);
    if (current_page != nb_main_page_downloads)
        looking = FALSE;

	if (!looking) {
		switch (d->status) {
		case GTA_DL_ACTIVE_QUEUED:
		case GTA_DL_RECEIVING:
		case GTA_DL_IGNORING:
		case GTA_DL_HEADERS:
		case GTA_DL_PUSH_SENT:
		case GTA_DL_CONNECTING:
		case GTA_DL_REQ_SENDING:
		case GTA_DL_REQ_SENT:
		case GTA_DL_FALLBACK:
		case GTA_DL_SINKING:
		case GTA_DL_TIMEOUT_WAIT:
		case GTA_DL_VERIFYING:
		case GTA_DL_MOVING:
			return;			/* This will be updated when they look */
		default:
			break;			/* Other states must always be updated */
		}
	}

    color = &(gtk_widget_get_style(GTK_WIDGET(ctree_downloads))
        ->fg[GTK_STATE_INSENSITIVE]);

	d->last_gui_update = now;
	fi = d->file_info;

	switch (d->status) {
	case GTA_DL_ACTIVE_QUEUED:	/* JA, 31 jan 2003 Active queueing */
		{
			time_delta_t elapsed;
			
			elapsed = delta_time(now, d->last_update);
			elapsed = MAX(0, elapsed);
			elapsed = MIN(elapsed, INT_MAX);
			
			rw = gm_snprintf(tmpstr, sizeof(tmpstr), _("Queued"));

			if (guc_get_parq_dl_position(d) > 0) {

				rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					_(" (slot %d"),		/* ) */
					guc_get_parq_dl_position(d));

				if (guc_get_parq_dl_queue_length(d) > 0) {
					rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
						"/%d", guc_get_parq_dl_queue_length(d));
				}

				if (guc_get_parq_dl_eta(d)  > 0) {
					rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
						_(", ETA: %s"),
						short_time((guc_get_parq_dl_eta(d)
							- elapsed)));
				}

				rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw, /* ( */ ")");
			}

			rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					_(" retry in %ds"),
					(gint) (guc_get_parq_dl_retry_delay(d) - elapsed));

			if (
				parent_gui_needs_update(d, now) &&
				(
					!downloads_gui_any_status(d, GTA_DL_RECEIVING) &&
					!downloads_gui_any_status(d, GTA_DL_IGNORING)
				)
			)
				downloads_gui_update_parent_status(d, now, _("Queued"));
		}

		/*
		 * If source is a partial source, show it.
		 */

		if (d->ranges != NULL) {
			gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
				" <PFS %4.02f%%>", d->ranges_size * 100.0 / fi->size);
		}

		a = tmpstr;
		break;
	case GTA_DL_QUEUED:
		a = d->remove_msg ? d->remove_msg : "";
		break;

	case GTA_DL_CONNECTING:
		a = _("Connecting...");
		if (
			parent_gui_needs_update(d, now) &&
			!downloads_gui_any_status(d, GTA_DL_RECEIVING) &&
			!downloads_gui_any_status(d, GTA_DL_ACTIVE_QUEUED)
		)
			downloads_gui_update_parent_status(d, now, _("Connecting..."));
		break;

	case GTA_DL_PUSH_SENT:
	case GTA_DL_FALLBACK:
		{
			if (d->cproxy != NULL) {
				const struct cproxy *cp = d->cproxy;

				if (cp->done) {
					if (cp->sent)
						rw = gm_snprintf(tmpstr, sizeof(tmpstr),
								cp->directly
									? _("Push sent directly")
									: _("Push sent"));
					else
						rw = gm_snprintf(tmpstr, sizeof(tmpstr),
								_("Failed to send push"));
				} else
					rw = gm_snprintf(tmpstr, sizeof(tmpstr),
							_("Sending push"));

				rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw, _(" via %s"),
						host_addr_port_to_string(cproxy_addr(cp),
							cproxy_port(cp)));

				if (!cp->done) {
					switch (cp->state) {
					case HTTP_AS_CONNECTING:	a = _("Connecting"); break;
					case HTTP_AS_REQ_SENDING:	a = _("Sending request"); break;
					case HTTP_AS_REQ_SENT:		a = _("Request sent"); break;
					case HTTP_AS_HEADERS:		a = _("Reading headers"); break;
					default:					a = "..."; break;
					}

					rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
						": %s", a);
				}

				a = tmpstr;
			} else {
				switch (d->status) {
				case GTA_DL_PUSH_SENT:
					a = _("Push sent");
					if (
						parent_gui_needs_update(d, now) &&
						!downloads_gui_any_status(d, GTA_DL_RECEIVING) &&
						!downloads_gui_any_status(d, GTA_DL_ACTIVE_QUEUED) &&
						!downloads_gui_any_status(d, GTA_DL_CONNECTING)
						)
						downloads_gui_update_parent_status
							(d, now, _("Push sent"));
					break;
				case GTA_DL_FALLBACK:
					a = _("Falling back to push");
					break;
				default:
					break;
				}
			}
		}
		break;

	case GTA_DL_REQ_SENDING:
		if (d->req != NULL) {
			gint pct = guc_download_get_http_req_percent(d);
			gm_snprintf(tmpstr, sizeof(tmpstr), _("Sending request (%d%%)"),
				pct);
			a = tmpstr;
		} else
			a = _("Sending request");
		break;

	case GTA_DL_REQ_SENT:
		a = _("Request sent");
		break;

	case GTA_DL_HEADERS:
		a = _("Receiving headers");
		break;

	case GTA_DL_ABORTED:
		a = d->unavailable ? _("Aborted (Server down)") : _("Aborted");

		/*
		 * If this download is aborted, it's possible all the downloads in this
	     * parent node (if there is one) are aborted too. If so, update parent
		 */

		if (downloads_gui_all_aborted(d))
			downloads_gui_update_parent_status(d, now, _("Aborted"));

		break;

	case GTA_DL_COMPLETED:
		if (d->last_update != d->start_date) {
			time_delta_t t = delta_time(d->last_update, d->start_date);
			
			gm_snprintf(tmpstr, sizeof(tmpstr), "%s (%s) %s",
				FILE_INFO_COMPLETE(fi) ? _("Completed") : _("Chunk done"),
				short_rate((d->range_end - d->skip + d->overlap_size) / t,
					show_metric_units()),
				short_time(t));
		} else {
			gm_snprintf(tmpstr, sizeof(tmpstr), "%s (< 1s)",
				FILE_INFO_COMPLETE(fi) ? _("Completed") : _("Chunk done"));
		}
		a = tmpstr;
		break;

	case GTA_DL_VERIFY_WAIT:
		g_assert(FILE_INFO_COMPLETE(fi));
		g_strlcpy(tmpstr, _("Waiting for SHA1 checking..."), sizeof(tmpstr));
		copy_status_to_parent = TRUE;		/* In active pane */
		a = tmpstr;
		break;

	case GTA_DL_VERIFYING:
		g_assert(FILE_INFO_COMPLETE(fi));
		gm_snprintf(tmpstr, sizeof(tmpstr),
			_("Computing SHA1 (%.02f%%)"), fi->cha1_hashed * 100.0 / fi->size);
		copy_status_to_parent = TRUE;		/* In active pane */
		a = tmpstr;
		break;

	case GTA_DL_VERIFIED:
	case GTA_DL_MOVE_WAIT:
	case GTA_DL_MOVING:
	case GTA_DL_DONE:
		g_assert(FILE_INFO_COMPLETE(fi));
		g_assert(fi->cha1_hashed <= fi->size);
		copy_status_to_parent = TRUE;		/* In active pane */
		{
			gboolean sha1_ok = fi->cha1 &&
				(fi->sha1 == NULL || sha1_eq(fi->sha1, fi->cha1));

			rw = gm_snprintf(tmpstr, sizeof(tmpstr), "SHA1 %s %s",
				fi->sha1 == NULL ? "figure" : "check",
				fi->cha1 == NULL ?	"ERROR" :
				sha1_ok ?			"OK" :
									"FAILED");
			if (fi->cha1 && fi->cha1_hashed) {
				guint elapsed = fi->cha1_elapsed;
			
				rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					" (%s) %s",
					short_rate(fi->cha1_hashed / (elapsed ? elapsed : 1),
						show_metric_units()),
					short_time(fi->cha1_elapsed));
			}

			switch (d->status) {
			case GTA_DL_MOVE_WAIT:
				g_strlcpy(&tmpstr[rw], _("; Waiting for moving..."),
					sizeof(tmpstr)-rw);
				break;
			case GTA_DL_MOVING:
				gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					_("; Moving (%.02f%%)"), fi->copied * 100.0 / fi->size);
				break;
			case GTA_DL_DONE:
				if (fi->copy_elapsed) {
					gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
						_("; Moved (%s) %s"),
						short_rate(fi->copied / fi->copy_elapsed,
							show_metric_units()),
						short_time(fi->copy_elapsed));
				}
				break;
			default:
				break;
			}
		}
		a = tmpstr;
		break;

	case GTA_DL_RECEIVING:
	case GTA_DL_IGNORING:
		if (d->pos + download_buffered(d) > d->skip) {
			gint bps;
			guint32 avg_bps;
			filesize_t downloaded;

			downloaded = d->pos - d->skip + download_buffered(d);

			if (d->bio) {
				bps = bio_bps(d->bio);
				avg_bps = bio_avg_bps(d->bio);
			} else {
				avg_bps = 0;
				bps = 0;
			}

			if (avg_bps <= 10 && d->last_update != d->start_date)
				avg_bps = downloaded / (d->last_update - d->start_date);

			rw = 0;

			if (avg_bps) {
				filesize_t remain = 0;
				guint32 s;

                if (d->size > downloaded)
                    remain = d->size - downloaded;

                s = remain / avg_bps;

				if (delta_time(now, d->last_update) > IO_STALLED)
					rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw, " %s",
						_("(stalled)"));
				else
					rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
						" (%s)", short_rate(bps, show_metric_units()));

				rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					_(" [%d/%d] TR: %s"), fi->recvcount, fi->lifecount,
					s ? short_time(s) : "-");

				if (fi->recv_last_rate) {
					s = (fi->size - fi->done) / fi->recv_last_rate;

					rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
						" / %s", short_time(s));

					if (fi->recvcount > 1) {
						rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
							" (%s)", short_rate(fi->recv_last_rate,
										show_metric_units()));
					}
				}
			} else {
				rw = gm_snprintf(tmpstr, sizeof(tmpstr), "%4.02f%% %s",
					  guc_download_source_progress(d),
					  delta_time(now, d->last_update) > IO_STALLED
					  	? _("(stalled)") : "");
			}

			/*
			 * If source is a partial source, show it.
			 */

			if (d->ranges != NULL)
				rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					" <PFS %4.02f%%>", d->ranges_size * 100.0 / fi->size);

			/*
			 * If more than one request served with the same connection,
			 * show them how many were served (adding 1 for current request).
			 */

			if (d->served_reqs)
				rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					" #%u", d->served_reqs + 1);

			if (GTA_DL_IGNORING == d->status)
				rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					" (%s)", _("ignoring"));

			a = tmpstr;
		} else
			a = _("Connected");
		break;

	case GTA_DL_ERROR:
		a = d->remove_msg ? d->remove_msg : _("Unknown error");
		break;

	case GTA_DL_TIMEOUT_WAIT:
		{
			time_delta_t when;
			
			when = d->timeout_delay - delta_time(now, d->last_update);
			when = MAX(0, when);
			when = MIN(when, INT_MAX);
			gm_snprintf(tmpstr, sizeof(tmpstr), _("Retry in %us"),
				(unsigned) when);
		}
		a = tmpstr;
		break;
	case GTA_DL_SINKING:
		{
			gchar buf[UINT64_DEC_BUFLEN];
			
			uint64_to_string_buf(d->sinkleft, buf, sizeof buf);
			gm_snprintf(tmpstr, sizeof(tmpstr),
				_("Sinking (%s bytes left)"), buf);
		}
		a = tmpstr;
		break;
	default:
		gm_snprintf(tmpstr, sizeof(tmpstr), "UNKNOWN STATUS %u",
				   d->status);
		a = tmpstr;
	}

	if (d->status != GTA_DL_TIMEOUT_WAIT)
		d->last_gui_update = now;

    if (d->status == GTA_DL_QUEUED) {
		node = gtk_ctree_find_by_row_data(ctree_queue, NULL, d);

		if (NULL != node) {
			gtk_ctree_node_set_text(ctree_queue, node,
				c_queue_status, a);
        	if (d->always_push)
        	     gtk_ctree_node_set_foreground(ctree_queue, node, color);
		}

		/*  Update header for downloads with multiple hosts */
		if (NULL != d->file_info) {

			key = GUINT_TO_POINTER(d->file_info->fi_handle);
			parent = find_parent_with_fi_handle(parents_queue, key);

			if (parent != NULL) {

				drecord = gtk_ctree_node_get_row_data(ctree_queue, parent);
				if (DL_GUI_IS_HEADER == drecord) {
					/* There is a header entry, we need to update it */

					/* Download is done */
					if (FILE_INFO_COMPLETE(d->file_info)) {
						gm_snprintf(tmpstr, sizeof(tmpstr), _("Complete"));
						gtk_ctree_node_set_text(ctree_queue, parent,
							c_queue_status, tmpstr);
					}
				}
			}
		}
	} else {  /* Is an active downloads */

		node = gtk_ctree_find_by_row_data(ctree_downloads, NULL, (gpointer) d);

		/* Update status column */
		if (NULL != node) {
			gtk_ctree_node_set_text(ctree_downloads, node, c_dl_status, a);
			gtk_ctree_node_set_text(ctree_downloads, node,
				c_dl_progress, source_progress_to_string(d));
    	    if (DOWNLOAD_IS_IN_PUSH_MODE(d))
        	     gtk_ctree_node_set_foreground(ctree_downloads, node, color);
		}


		/*  Update header for downloads with multiple hosts */
		if (NULL != d->file_info) {

			key = GUINT_TO_POINTER(d->file_info->fi_handle);
			parent = find_parent_with_fi_handle(parents, key);

			if (
				parent != NULL &&
				now != get_last_parent_gui_update(key)
			) {
				drecord = gtk_ctree_node_get_row_data(ctree_downloads, parent);

				if (DL_GUI_IS_HEADER == drecord) {
					/* There is a header entry, we need to update it */

					gtk_ctree_node_set_text(ctree_downloads, parent,
						c_dl_progress, download_progress_to_string(d));
					
					if (copy_status_to_parent) {
						/* Download is done */

						gtk_ctree_node_set_text(ctree_downloads, parent,
							c_dl_status, a);
						record_parent_gui_update(key, now);

					} else if (
						GTA_DL_RECEIVING == d->status ||
						GTA_DL_IGNORING == d->status
					) {
						guint32 s;

						active_src = fi->recvcount;
						tot_src = fi->lifecount;

						if (fi->recv_last_rate)
							s = (fi->size - fi->done) / fi->recv_last_rate;
						else
							s = 0;

						if (s) {
							gm_snprintf(tmpstr, sizeof(tmpstr),
								_("(%s)  [%d/%d]  TR:  %s"),
								short_rate(fi->recv_last_rate,
									show_metric_units()),
								active_src, tot_src, short_time(s));
						} else {
							gm_snprintf(tmpstr, sizeof(tmpstr),
								_("(%s)  [%d/%d]  TR:  -"),
								short_rate(fi->recv_last_rate,
									show_metric_units()),
								active_src, tot_src);
						}

						gtk_ctree_node_set_text(ctree_downloads,
							parent, c_dl_status, tmpstr);
						record_parent_gui_update(key, now);
					}
				}
			}
		}
	}
}


void
gui_update_download_abort_resume(void)
{
   	struct download *d;
    GList *node_list;
    GList *data_list;
    GList *l;

	gboolean do_abort  = FALSE;
    gboolean do_resume = FALSE;
    gboolean do_remove = FALSE;
    gboolean do_queue  = FALSE;
    gboolean abort_sha1 = FALSE;

	/*
	 * settings_gui_init() triggers this function before downloads_gui_init()
	 * has run.
	 */
	if (NULL == ctree_downloads)
		return;

    node_list = g_list_copy(GTK_CLIST(ctree_downloads)->selection);
	data_list = downloads_gui_collect_ctree_data(ctree_downloads,
		node_list, FALSE, TRUE);

    for (l = data_list; NULL != l; l = g_list_next(l)) {
		d = l->data;
        if (NULL == d) {
			g_warning("gui_update_download_abort_resume(): row has NULL data");
			continue;
		}

		download_check(d);
		g_assert(d->status != GTA_DL_REMOVED);

		switch (d->status) {
		case GTA_DL_COMPLETED:
		case GTA_DL_VERIFY_WAIT:
		case GTA_DL_VERIFYING:
		case GTA_DL_VERIFIED:
			break;
		default:
			do_queue = TRUE;
			break;
		}

        if (d->file_info->sha1 != NULL)
            abort_sha1 = TRUE;

		switch (d->status) {
		case GTA_DL_QUEUED:
			g_warning("gui_update_download_abort_resume(): "
				"found queued download '%s' in active download list !",
				d->file_name);
			continue;
		case GTA_DL_CONNECTING:
		case GTA_DL_PUSH_SENT:
		case GTA_DL_FALLBACK:
		case GTA_DL_REQ_SENT:
		case GTA_DL_HEADERS:
		case GTA_DL_RECEIVING:
		case GTA_DL_IGNORING:
		case GTA_DL_ACTIVE_QUEUED:
		case GTA_DL_SINKING:
			do_abort = TRUE;
			break;
		case GTA_DL_ERROR:
		case GTA_DL_ABORTED:
			do_resume = TRUE;
            /* only check if file exists if really necessary */
            if (!do_remove && guc_download_file_exists(d))
                do_remove = TRUE;
			break;
		case GTA_DL_TIMEOUT_WAIT:
			do_abort = do_resume = TRUE;
			break;
        default:
			break;
		}
		if (do_abort & do_resume & do_remove)
			break;
	}

	g_list_free(data_list);
	g_list_free(node_list);

	gtk_widget_set_sensitive
        (gui_main_window_lookup("button_downloads_abort"), do_abort);
	gtk_widget_set_sensitive
        (gui_popup_downloads_lookup("popup_downloads_abort"), do_abort);
    gtk_widget_set_sensitive
        (gui_popup_downloads_lookup("popup_downloads_abort_named"),
		do_abort);
    gtk_widget_set_sensitive
        (gui_popup_downloads_lookup("popup_downloads_abort_host"),
		do_abort);
    gtk_widget_set_sensitive(
        gui_popup_downloads_lookup("popup_downloads_abort_sha1"),
        abort_sha1);
	gtk_widget_set_sensitive
        (gui_main_window_lookup("button_downloads_resume"), do_resume);
	gtk_widget_set_sensitive
        (gui_popup_downloads_lookup("popup_downloads_resume"), do_resume);
    gtk_widget_set_sensitive
        (gui_popup_downloads_lookup("popup_downloads_remove_file"),
		do_remove);
    gtk_widget_set_sensitive
        (gui_popup_downloads_lookup("popup_downloads_queue"), do_queue);
}

/**
 * Remove a download from the GUI.
 */
void
download_gui_remove(struct download *d)
{
	GtkCTreeNode *node, *parent;
	GtkCTreeRow *parent_row;
	struct download *drecord;
	gchar *host, *range, *server, *status, *country, *progress;
	const gchar *filename;
	gpointer key;
	gint n;

	g_return_if_fail(d);

	if (!DOWNLOAD_IS_VISIBLE(d)) {
		g_warning
			("download_gui_remove() called on invisible download '%s' !",
			 d->file_name);
		return;
	}


	if (DOWNLOAD_IS_QUEUED(d)) {
		node = gtk_ctree_find_by_row_data(ctree_queue, NULL, d);

		if (NULL != node) {
			/*  We need to discover if the download has a parent */
			if (NULL != d->file_info) {

				key = GUINT_TO_POINTER(d->file_info->fi_handle);
				parent =  find_parent_with_fi_handle(parents_queue, key);

				if (NULL != parent) {

					n = parent_children_add(ctree_queue, key, 0);

					/* If there are children, there should be >1 */
					if (1 == n || n < 0) {
						g_warning("gui_remove_download (queued):"
							"node has %d children!", n);
						return;
					}

					if (2 == n) {
						/* Removing this download will leave only one left,
						 * we'll have to get rid of the header. */

						/* Get rid of current download, d */
						gtk_ctree_remove_node(ctree_queue, node);
						parent_children_add(ctree_queue, key, -1);

						/* Replace header with only remaining child */
						parent_row = GTK_CTREE_ROW(parent);
						node = parent_row->children;

						drecord = gtk_ctree_node_get_row_data(ctree_queue,
									node);
						filename = guc_file_info_readable_filename(
									drecord->file_info);
						gtk_ctree_node_get_text(ctree_queue, node,
							c_queue_host, &host);
						gtk_ctree_node_get_text(ctree_queue, node,
							c_queue_server, &server);
						gtk_ctree_node_get_text(ctree_queue, node,
							c_queue_status, &status);
						gtk_ctree_node_get_text(ctree_queue, node,
							c_queue_loc, &country);

						gtk_ctree_node_set_row_data(ctree_queue,
							parent, drecord);
						gtk_ctree_node_set_text(ctree_queue, parent,
							c_queue_host, filename);
						gtk_ctree_node_set_text(ctree_queue, parent,
							c_queue_host, host);
						gtk_ctree_node_set_text(ctree_queue, parent,
							c_queue_server, server);
						gtk_ctree_node_set_text(ctree_queue, parent,
							c_queue_status, status);
						gtk_ctree_node_set_text(ctree_queue, parent,
							c_queue_loc, country);
					} else if (0 == n) {
						/* Node has no children -> is a parent */
						remove_parent_with_fi_handle(parents_queue,
							d->file_info->fi_handle);
					} else if (n > 2) {
						guint v = n - 1;
						
						gm_snprintf(tmpstr, sizeof(tmpstr),
							NG_("%u host", "%u hosts", v), v);

						gtk_ctree_node_set_text(ctree_queue,  parent,
							c_queue_host, tmpstr);
					}

					/*  Note: this line IS correct for cases n=0, n=2,and n>2 */
					gtk_ctree_remove_node(ctree_queue, node);
					if (n > 0)
						parent_children_add(ctree_queue, key, -1);

				} else
					g_warning("download_gui_remove(): "
						"Download '%s' has no parent", d->file_name);
			}
		} else
			g_warning("download_gui_remove(): "
				"Queued download '%s' not found in treeview !?", d->file_name);

	} else { /* Removing active download */

		node = gtk_ctree_find_by_row_data(ctree_downloads, NULL, (gpointer) d);

		if (NULL != node) {
			/*  We need to discover if the download has a parent */
			if (NULL != d->file_info) {

				key = GUINT_TO_POINTER(d->file_info->fi_handle);
				parent = find_parent_with_fi_handle(parents, key);

				if (NULL != parent) {

					n = parent_children_add(ctree_downloads, key, 0);

					/* If there are children, there should be >1 */
					if (1 == n || n < 0) {
						g_warning("gui_remove_download (active):"
							"node has %d children!", n);
						return;
					}

					if (2 == n) {
						/* Removing this download will leave only one left,
						 * we'll have to get rid of the header. */

						/* Get rid of current download, d */
						gtk_ctree_remove_node(ctree_downloads, node);
						parent_children_add(ctree_downloads, key, -1);

						/* Replace header with only remaining child */
						parent_row = GTK_CTREE_ROW(parent);
						node = parent_row->children;

						drecord = gtk_ctree_node_get_row_data
							(ctree_downloads, node);
						filename =
							guc_file_info_readable_filename
							(drecord->file_info);
						gtk_ctree_node_get_text(ctree_downloads, node,
							c_dl_host, &host);
						gtk_ctree_node_get_text(ctree_downloads, node,
							c_dl_server, &server);
						gtk_ctree_node_get_text(ctree_downloads, node,
							c_dl_progress, &progress);
						gtk_ctree_node_get_text(ctree_downloads, node,
							c_dl_status, &status);
						gtk_ctree_node_get_text(ctree_downloads, node,
							c_dl_range, &range);
						gtk_ctree_node_get_text(ctree_downloads, node,
							c_dl_loc, &country);

						gtk_ctree_node_set_row_data(ctree_downloads, parent,
							drecord);
						gtk_ctree_node_set_text(ctree_downloads,  parent,
							c_dl_host, filename);
						gtk_ctree_node_set_text(ctree_downloads,  parent,
							c_dl_host, host);
						gtk_ctree_node_set_text(ctree_downloads,  parent,
							c_dl_server, server);
						gtk_ctree_node_set_text(ctree_downloads,  parent,
							c_dl_progress, progress);
						gtk_ctree_node_set_text(ctree_downloads,  parent,
							c_dl_status, status);
						gtk_ctree_node_set_text(ctree_downloads,  parent,
							c_dl_range, range);
						gtk_ctree_node_set_text(ctree_downloads,  parent,
							c_dl_loc, country);
					} else if (0 == n) {
						/* Node has no children -> is a parent */
						remove_parent_with_fi_handle(parents,
							d->file_info->fi_handle);
					} else if (2 < n){
						guint v = n - 1;
						
						gm_snprintf(tmpstr, sizeof(tmpstr),
							NG_("%u host", "%u hosts", v), v);
						gtk_ctree_node_set_text(ctree_downloads,  parent,
							c_dl_host, tmpstr);
					}

					/*  Note: this line IS correct for cases n=0, n=2,and n>2 */
					gtk_ctree_remove_node(ctree_downloads, node);
					if (n > 0)
						parent_children_add(ctree_downloads, key, -1);

				} else
					g_warning("download_gui_remove(): "
						"Active download '%s' has no parent", d->file_name);
			}
		} else
			g_warning("download_gui_remove(): "
				"Active download '%s' not found in treeview!?",  d->file_name);
	}

	d->visible = FALSE;

	gui_update_download_abort_resume();
	gui_update_download_clear();
}

/**
 *	Collapse all nodes in given, tree either downloads or downloads_queue
 */
void
downloads_gui_expand_all(GtkCTree *ctree)
{
	gtk_ctree_expand_recursive(ctree, NULL);
	downloads_update_active_pane();
}


/**
 *	Collapse all nodes in given, tree either downloads or downloads_queue
 */
void
downloads_gui_collapse_all(GtkCTree *ctree)
{
	gtk_ctree_collapse_recursive(ctree, NULL);
	downloads_update_active_pane();
}

/**
 * Update "active" pane if needed.
 */
void
downloads_update_active_pane(void)
{
	GtkCList *clist = GTK_CLIST(ctree_downloads);

	if (!ctree_downloads_frozen)
		return;

	gtk_clist_thaw(clist);
	gtk_clist_freeze(clist);
}

/**
 * Update "queue" pane if needed.
 */
void
downloads_update_queue_pane(void)
{
	GtkCList *clist = GTK_CLIST(ctree_queue);

	if (!ctree_queue_frozen)
		return;

	gtk_clist_thaw(clist);
	gtk_clist_freeze(clist);
}

/**
 * Periodically called to update downloads display.
 */
void
downloads_gui_update_display(time_t unused_now)
{
	GtkCList *clist;
	gboolean *frozen;
    gint current_page;

	(void) unused_now;

    current_page = gtk_notebook_get_current_page(GTK_NOTEBOOK(
						gui_main_window_lookup("notebook_downloads")));

	/*
	 * We make sure the trees are frozen, so that no GUI redrawing ever
	 * takes place until we're called here and they are watching.
	 */

    if (current_page == nb_downloads_page_active) {
		frozen = &ctree_downloads_frozen;
		clist = GTK_CLIST(ctree_downloads);
	} else if (current_page == nb_downloads_page_queued) {
		frozen = &ctree_queue_frozen;
		clist = GTK_CLIST(ctree_queue);
	} else {
		/*
		 * They're not looking, no need to update the visuals!
		 */

		frozen = NULL;
		clist = NULL;

		if (!ctree_downloads_frozen) {
			clist = GTK_CLIST(ctree_downloads);
			gtk_clist_freeze(clist);
			ctree_downloads_frozen = TRUE;
		}
		if (!ctree_queue_frozen) {
			clist = GTK_CLIST(ctree_queue);
			gtk_clist_freeze(clist);
			ctree_queue_frozen = TRUE;
		}

		return;
	}

	if (!main_gui_window_visible())
		return;

	g_assert(frozen != NULL);

	if (*frozen)
		gtk_clist_thaw(clist);		/* Will update visuals */

	gtk_clist_freeze(clist);
	*frozen = TRUE;
}

void
downloads_gui_clear_details(void)
{
	GtkCList *clist;

	clist = GTK_CLIST(gui_main_window_lookup("clist_download_details"));
	g_return_if_fail(clist);

    gtk_clist_clear(clist);
}

void
downloads_gui_append_detail(const gchar *name, const gchar *value)
{
 	const gchar *titles[2];
	GtkCList *clist;

	clist = GTK_CLIST(gui_main_window_lookup("clist_download_details"));
	g_return_if_fail(clist);

	titles[0] = name;
	titles[1] = EMPTY_STRING(value);
    gtk_clist_append(clist, (gchar **) titles);
}

/* vi: set ts=4 sw=4 cindent: */
