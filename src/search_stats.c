/*
 * search_stats.c - keep track of what search terms we have seen, and 
 *					how frequently each has been seen.
 *
 *		this uses the glib hash tables and lists, but a much more efficient
 *		implementation could be done with a specialized hash table /
 *		re-keyable binary tree. (TODO?)	would be easy in c++.
 *
 *		(C) 2002 Michael Tesch, released with gtk-gnutella & its license
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#include "gnutella.h"

#include "interface.h"
#include "search_stats.h"

/* this is what the stat_hash's 'val' points to */
struct term_counts {
	guint32 period_cnt;
	guint32 total_cnt;
	guint32 periods;
};

gboolean search_stats_enabled = FALSE;
static guint32 stat_count;

static GHashTable *stat_hash = NULL;

static gboolean delete_hash_entry(gpointer key, gpointer val, gpointer data);
static int update_search_stats_display(gpointer data);
static void empty_hash_table();
static gboolean stats_hash_to_clist(
	gpointer key, gpointer value, gpointer userdata);

static gboolean
delete_hash_entry(gpointer key, gpointer val, gpointer data)
{
	/* free the key str (was strdup'd below) */
	g_free(key);
	g_free(val);
	return TRUE;
}

/* this sucks -- too slow */
static void empty_hash_table()
{
	if (!stat_hash)
		return;

	g_hash_table_foreach_remove(stat_hash, delete_hash_entry, NULL);
}

void enable_search_stats()
{
	if (!stat_hash) {
		stat_hash = g_hash_table_new(g_str_hash, g_str_equal);

		/* set up the clist to be sorted properly */
		gtk_clist_set_auto_sort(GTK_CLIST(clist_search_stats), TRUE);
		gtk_clist_set_sort_column(GTK_CLIST(clist_search_stats), 2);
		gtk_clist_set_sort_type(GTK_CLIST(clist_search_stats),
			GTK_SORT_DESCENDING);
		/*	gtk_clist_set_compare_func(clist_search_stats, ); */
	}

	/* XXX: if someone clicks the 'Enable Search Stats' on and off a bunch
	 * this will end up scheduling a bunch of update_search_stats_display()s
	 * stupid glib doesn't allow de-scheduling or checking of timers. */

	g_timeout_add(100 * search_stats_update_interval,
		update_search_stats_display, NULL);
}


/* helper func for stats_display */
static gboolean
stats_hash_to_clist(gpointer key, gpointer value, gpointer userdata)
{
	gchar *text[3];
	gchar period_tmp[32];
	gchar total_tmp[32];
	struct term_counts *val = (struct term_counts *) value;

	/* update counts */
	if (!val->period_cnt)
		val->periods++;
	else
		val->periods = 0;
	val->total_cnt += val->period_cnt;

	/* try to keep the number of infrequent terms down */
	if (((float) val->total_cnt / (float) (val->periods + 2)) * 100 < search_stats_delcoef) {
		g_free(key);
		g_free(val);
		return TRUE;
	}

	stat_count++;

	/* update the display */

	g_snprintf(period_tmp, sizeof(period_tmp), "%8.8d", (int) val->period_cnt);
	g_snprintf(total_tmp, sizeof(total_tmp), "%8.8d", (int) val->total_cnt);

	text[0] = (gchar *) key;
	text[1] = period_tmp;
	text[2] = total_tmp;
	gtk_clist_insert(GTK_CLIST(clist_search_stats), 0, text);

	/* new period begins */
	val->period_cnt = 0;

	return FALSE;
}

/*
 * Display the data gathered during the last time period.
 * Perhaps it would be better to have this done on a button click(?)
 */
static int update_search_stats_display(gpointer data)
{
	static guint32 last_update_interval;
	char tmpstr[32];

	/* if search_stats were disabled during this interval */
	if (!search_stats_enabled) {
		gtk_widget_set_sensitive(checkbutton_enable_search_stats, TRUE);
		return FALSE;
	}

	stat_count = 0;
	gtk_clist_freeze(GTK_CLIST(clist_search_stats));

	gtk_clist_clear(GTK_CLIST(clist_search_stats));

	/* insert the hash table contents into the sorted clist */
	g_hash_table_foreach_remove(stat_hash, stats_hash_to_clist, NULL);

	gtk_clist_thaw(GTK_CLIST(clist_search_stats));

	/* update the counter */
	g_snprintf(tmpstr, sizeof(tmpstr), "%u", stat_count);
	gtk_label_set_text(GTK_LABEL(label_search_stats_count), tmpstr);

	/* reschedule? */
	if (last_update_interval != search_stats_update_interval) {
		last_update_interval = search_stats_update_interval;
		g_timeout_add(100 * search_stats_update_interval,
					  update_search_stats_display, NULL);
		return FALSE;
	}
	return TRUE;
}

/*
 * Clear the list, empty the hash table.
 */
void reset_search_stats()
{
	empty_hash_table();
	gtk_clist_clear(GTK_CLIST(clist_search_stats));

	/* if no longer in use, free up all the mem */
	if (!search_stats_enabled) {
		g_hash_table_destroy(stat_hash);
		stat_hash = NULL;
	}
}

/*
 * Count a word that has been seen.
 */
void tally_search_stats(const word_vec_t * vec)
{
	struct term_counts *val;
	gpointer key;

	if (vec->word[1] == '\0' || vec->word[2] == '\0')
		return;

	val = g_hash_table_lookup(stat_hash, vec->word);
	if (val) {
		val->period_cnt++;
	} else {
		key = g_strdup(vec->word);
		val = (struct term_counts *) g_malloc0(sizeof(struct term_counts));
		val->period_cnt = vec->amount;
		g_hash_table_insert(stat_hash, key, (gpointer) val);
	}
}

