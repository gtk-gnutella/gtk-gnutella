
#ifndef __search_h__
#define __search_h__

#include <time.h>

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

struct search
{
	GtkWidget *clist;						/* GtkCList for this search */
	GtkWidget *scrolled_window;		/* GtkScrolledWindow containing the GtkCList */
	GtkWidget *list_item;				/* The GtkListItem in the combo for this search */
	gchar 	*query;						/* The search query */
	guint16	speed;						/* Minimum speed for the results of this query */
	time_t	time;							/* Time when this search was started */
	GSList  *muids;						/* Message UID's of this search */
	GSList	*r_sets;						/* The results sets of this search */
	guint32	items;						/* Total number of items for this search */

	gint sort_col;							/* Column to sort */
	gint sort_order;						/* Ascending or descending */
	gboolean sort;							/* Do sorting or not */

	gpointer filter_page;				/* Page of filters in the filters notebook */

	time_t last_update_time;             /* the last time the notebook tab was updated. */
	guint32 last_update_items;           /* Number of items included in last update */
	gint tab_updating;                   /* token identifying timeout function to be canceled. */
	guint32 unseen_items;                /* How many items haven't been seen yet. */

	gboolean passive;                    /* Is this a passive search?  Maybe this would be better done with a magic muid. */
	GHashTable *dups; /* keep a record of dups. */

	GHook *gh;
	/* XXX Other fields for the filtering will be added here */
};

extern GSList *searches;							/* List of search structs */

#endif	/* __search_h__ */

/* vi: set ts=3: */

