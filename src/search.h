
#ifndef __search_h__
#define __search_h__

#include <time.h>
#include "nodes.h"

struct gnutella_search {
	guchar speed[2];
	guchar query[0];
};

struct gnutella_search_results {
	guchar num_recs;
	guchar host_port[2];
	guchar host_ip[4];
	guchar host_speed[4];
	guchar records[0];

	/* Last 16 bytes = client_id */
};

struct results_set {
	guchar guid[16];
	guint32 num_recs;
	guint32 ip;
	guint16 port;
	guint16 status;				/* Parsed status bits from trailer */
	guint32 speed;
	guint32 trailer_len;		/* Length of the trailer data */
	gchar *trailer;				/* Raw trailer data */

	GSList *records;
};

/*
 * Flags for the `status' field above.
 */

#define ST_KNOWN_VENDOR			0x8000		/* Found known vendor code */
#define ST_PARSED_TRAILER		0x4000		/* Was able to parse trailer */
#define ST_UPLOADED				0x0004
#define ST_BUSY					0x0002
#define ST_FIREWALL				0x0001

struct record {
	struct results_set *results_set;
	gchar *name;				/* File name */
	guint32 size;				/* Size of file, in bytes */
	guint32 index;				/* Index for GET command */
	gchar *tag;					/* Optional tag data, NUL terminated */
};

struct gnutella_msg_search {
	struct gnutella_header header;
	struct gnutella_search search;
};

/* Structure for search results */
struct search {
	GtkWidget *clist;			/* GtkCList for this search */
	GtkWidget *scrolled_window; /* GtkScrolledWindow containing the GtkCList */
	GtkWidget *list_item;		/* The GtkListItem in combo for this search */
	gchar *query;				/* The search query */
	guint16 speed;				/* Minimum speed for the results of query */
	time_t time;				/* Time when this search was started */
	GSList *muids;				/* Message UID's of this search */
	GSList *r_sets;				/* The results sets of this search */
	guint32 items;				/* Total number of items for this search */

	gint sort_col;				/* Column to sort */
	gint sort_order;			/* Ascending or descending */
	gboolean sort;				/* Do sorting or not */

	gpointer filter_page;		/* Page of filters in the filters notebook */

	time_t last_update_time;	/* the last time the notebook tab was updated */
	guint32 last_update_items;	/* Number of items included in last update */
	gint tab_updating;			/* token for timeout function to be canceled. */
	guint32 unseen_items;		/* How many items haven't been seen yet. */

	gboolean passive;			/* Is this a passive search? */
	gboolean frozen;			/* True => don't update window */
	GHashTable *dups;			/* keep a record of dups. */
	/* keep a record of nodes we've sent this search w/ this muid to. */
	GHashTable *sent_nodes;

	GHook *new_node_hook;
	guint reissue_timeout_id;
	guint reissue_timeout;		/* timeout per search, 0 = search stopped */
	/* XXX Other fields for the filtering will be added here */
};

/*
 * Global Data
 */

extern GtkWidget *dialog_filters;
extern gboolean search_results_show_tabs;
extern guint32 search_passive;
extern guint32 search_reissue_timeout;
extern GSList *searches;			/* List of search structs */
extern guint32 search_max_results;	/* Max items allowed in GUI results */

/* flags for _new_search() */
#define SEARCH_PASSIVE	 0x01 /* start a passive search */

/*
 * Global Functions
 */

void search_init(void);
struct search *new_search(guint16, gchar *);
struct search *_new_search(guint16, gchar *, guint flags);
void search_stop(struct search *sch);
void search_resume(struct search *sch);
void search_results(struct gnutella_node *n);
void search_download_files(void);
void search_close_current(void);
void search_clear_clicked(void);
void search_update_reissue_timeout(guint32);
void search_shutdown(void);

#endif							/* __search_h__ */

/* vi: set ts=4: */
