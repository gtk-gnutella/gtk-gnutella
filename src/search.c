
#include <ctype.h>

/* Handle searches */

#include "gnutella.h"
#include "interface.h"
#include "misc.h"
#include "search.h"
#include "filter.h"
#include "downloads.h"
#include "gui.h"
#include "dialog-filters.h"
#include "autodownload.h"
#include "hosts.h"				/* For check_valid_host() */
#include "nodes.h"				/* For NODE_IS_PONGING_ONLY() */
#include "callbacks.h"
#include "routing.h"
#include "gmsg.h"

#define MAKE_CODE(a,b,c,d) ( \
	((guint32) (a) << 24) | \
	((guint32) (b) << 16) | \
	((guint32) (c) << 8)  | \
	((guint32) (d)))

#define T_BEAR	MAKE_CODE('B','E','A','R')
#define T_CULT	MAKE_CODE('C','U','L','T')
#define T_FIRE	MAKE_CODE('F','I','R','E')
#define T_FISH	MAKE_CODE('F','I','S','H')
#define T_GNEW	MAKE_CODE('G','N','E','W')
#define T_GNOT	MAKE_CODE('G','N','O','T')
#define T_GNUC	MAKE_CODE('G','N','U','C')
#define T_GNUT	MAKE_CODE('G','N','U','T')
#define T_GTKG	MAKE_CODE('G','T','K','G')
#define T_HSLG	MAKE_CODE('H','S','L','G')
#define T_LIME	MAKE_CODE('L','I','M','E')
#define T_MACT	MAKE_CODE('M','A','C','T')
#define T_MNAP	MAKE_CODE('M','N','A','P')
#define T_MRPH	MAKE_CODE('M','R','P','H')
#define T_MUTE	MAKE_CODE('M','U','T','E')
#define T_NAPS	MAKE_CODE('N','A','P','S')
#define T_OCFG	MAKE_CODE('O','C','F','G')
#define T_OPRA	MAKE_CODE('O','P','R','A')
#define T_PHEX	MAKE_CODE('P','H','E','X')
#define T_QTEL	MAKE_CODE('Q','T','E','L')
#define T_SNUT	MAKE_CODE('S','N','U','T')
#define T_SWAP	MAKE_CODE('S','W','A','P')
#define T_TOAD	MAKE_CODE('T','O','A','D')
#define T_XOLO	MAKE_CODE('X','O','L','O')
#define T_XTLA	MAKE_CODE('X','T','L','A')
#define T_ZIGA	MAKE_CODE('Z','I','G','A')

#define MAX_TAG_SHOWN	60		/* Show only first chars of tag */

static gchar stmp_2[4096];

GSList *searches = NULL;		/* List of search structs */

/* Need to remove this dependency on GUI further --RAM */
extern GtkWidget *default_search_clist;
extern GtkWidget *default_scrolled_window;

struct search *search_selected = NULL;
struct search *current_search = NULL;	/*	The search currently displayed */
gboolean search_results_show_tabs = TRUE;	/* Display the notebook tabs? */
guint32 search_max_results = 5000;		/* Max items allowed in GUI results */
guint32 search_passive = 0;				/* Amount of passive searches */

static void search_send_packet(struct search *);
static void search_add_new_muid(struct search *sch);
static guint sent_node_hash_func(gconstpointer key);
static gint sent_node_compare(gconstpointer a, gconstpointer b);
static void search_free_sent_nodes(struct search *sch);
static gboolean search_reissue_timeout_callback(gpointer data);
static void update_one_reissue_timeout(struct search *sch);
static struct results_set *get_results_set(struct gnutella_node *n);

/* ----------------------------------------- */

void search_reissue(struct search *sch)
{
	search_add_new_muid(sch);
	search_send_packet(sch);
	update_one_reissue_timeout(sch);
}

void search_restart(struct search *sch)
{
	search_reissue(sch);
	gtk_clist_clear(GTK_CLIST(sch->clist));
	sch->items = sch->unseen_items = 0;
	gui_search_update_items(sch);
}

void search_init(void)
{
	dialog_filters = create_dialog_filters();
	gui_search_init();
}

/*
 * search_free_record
 *
 * Free one file record.
 *
 * Those records may be inserted into some `dups' tables, at which time they
 * have their refcount increased.  They may later be removed from those tables
 * and they will have their refcount decreased.
 *
 * To ensure some level of sanity, we ask our callers to explicitely check
 * for a refcount to be zero before calling us.
 */
static void search_free_record(struct record *rc)
{
	g_assert(rc->refcount == 0);

	g_free(rc->name);
	if (rc->tag)
		g_free(rc->tag);
	g_free(rc);
}

/*
 * search_clean_r_set
 *
 * This routine must be called when the results_set has been dispatched to
 * all the opened searches.
 *
 * All the records that have not been used by a search are removed.
 */
static void search_clean_r_set(struct results_set *rs)
{
	GSList *m;

	g_assert(rs->refcount);		/* If not dispatched, should be freed */

again:
	for (m = rs->records; m; m = m->next) {
		struct record *rc = (struct record *) m->data;

		if (rc->refcount)
			continue;

		search_free_record(rc);
		rs->records = g_slist_remove(rs->records, rc);
		rs->num_recs--;

		goto again;				/* Need to restart from the beginning */
	}
}

/*
 * search_free_r_set
 *
 * Free one results_set.
 *
 * Those records may be shared between several searches.  So while the refcount
 * is positive, we just decrement it and return without doing anything.
 */
static void search_free_r_set(struct results_set *rs)
{
	GSList *m;

	/*
	 * It is conceivable that some records were used solely by the search
	 * dropping the result set.  Therefore, if the refcount is not 0,  we
	 * pass through search_clean_r_set().
	 */

	if (--(rs->refcount) > 0) {
		search_clean_r_set(rs);
		return;
	}

	/*
	 * Because noone refers to us any more, we know that our embedded records
	 * cannot be held in the hash table anymore.  Hence we may call the
	 * search_free_record() safely, because rc->refcount must be zero.
	 */

	for (m = rs->records; m; m = m->next)
		search_free_record((struct record *) m->data);

	if (rs->trailer)
		g_free(rs->trailer);
	g_slist_free(rs->records);
	g_free(rs);
}

/* Free all the results_set's of a search */

static void search_free_r_sets(struct search *sch)
{
	GSList *l;

	g_return_if_fail(sch);
	g_assert(sch->dups == NULL);	/* All records were cleaned */

	for (l = sch->r_sets; l; l = l->next)
		search_free_r_set((struct results_set *) l->data);

	g_slist_free(sch->r_sets);
	sch->r_sets = NULL;
}

/*
 * dec_records_refcount
 *
 * Decrement refcount of hash table key entry.
 */
static void dec_records_refcount(gpointer key, gpointer value, gpointer udata)
{
	struct record *rc = (struct record *) key;

	g_assert(rc->refcount > 0);

	rc->refcount--;
}

/* Close a search */

void search_close_current(void)
{
	GList *glist;
	GSList *m;
	struct search *sch = current_search;
   gboolean sensitive;

	g_return_if_fail(current_search);

	searches = g_slist_remove(searches, (gpointer) sch);

	gtk_timeout_remove(sch->tab_updating);

	if (!sch->passive) {
		g_hook_destroy_link(&node_added_hook_list, sch->new_node_hook);
		sch->new_node_hook = NULL;

		/* we could have stopped the search already, must test the ID */
		if (sch->reissue_timeout_id)
			g_source_remove(sch->reissue_timeout_id);

		for (m = sch->muids; m; m = m->next) {
			g_free(m->data);
		}

		g_slist_free(sch->muids);
		search_free_sent_nodes(sch);
	} else {
		search_passive--;
	}

	filters_close_search(sch);

	if (searches) {				/* Some other searches remain. */
		gtk_notebook_remove_page(GTK_NOTEBOOK(notebook_search_results),
			gtk_notebook_page_num(GTK_NOTEBOOK(notebook_search_results),
				sch->scrolled_window));
	} else {
		/*
		 * Keep the clist of this search, clear it and make it the
		 * default clist
		 */

		gtk_clist_clear(GTK_CLIST(sch->clist));

		default_search_clist = sch->clist;
		default_scrolled_window = sch->scrolled_window;

		search_selected = current_search = NULL;

		gui_search_update_items(NULL);

		gtk_entry_set_text(GTK_ENTRY(combo_entry_searches), "");

		if (search_results_show_tabs)
			gtk_notebook_set_show_tabs(GTK_NOTEBOOK(notebook_search_results),
				FALSE);

		gtk_widget_set_sensitive(button_search_clear, FALSE);
		gtk_widget_set_sensitive(popup_search_clear_results, FALSE);
	}

	/*
	 * Before invoking search_free_r_sets(), we must iterate on the
	 * hash table where we store records and decrement the refcount of
	 * each record.  Otherwise, we will violate the pre-condition of
	 * search_free_record(), which is there precisely for that reason!
	 */

	g_hash_table_foreach(sch->dups, dec_records_refcount, NULL);
	g_hash_table_destroy(sch->dups);
	sch->dups = NULL;

	search_free_r_sets(sch);

	glist = g_list_prepend(NULL, (gpointer) sch->list_item);

	gtk_list_remove_items(GTK_LIST(GTK_COMBO(combo_searches)->list), glist);

	g_free(sch->query);
	g_free(sch);

	gtk_widget_set_sensitive(combo_searches, (gboolean) searches);
	gtk_widget_set_sensitive(button_search_close, (gboolean) searches);

   sensitive = current_search && GTK_CLIST(current_search->clist)->selection;
   gtk_widget_set_sensitive(button_search_download, sensitive);
}

static gboolean search_free_sent_node(
	gpointer node, gpointer value, gpointer udata)
{
	g_free(node);
	return TRUE;
}

static void search_free_sent_nodes(struct search *sch)
{
	g_hash_table_foreach_remove(sch->sent_nodes, search_free_sent_node, NULL);
	g_hash_table_destroy(sch->sent_nodes);
}

static void search_reset_sent_nodes(struct search *sch)
{
	search_free_sent_nodes(sch);
	sch->sent_nodes =
		g_hash_table_new(sent_node_hash_func, sent_node_compare);
}

struct sent_node_data {
	guint32 ip;
	guint16 port;
};

static void mark_search_sent_to_node(struct search *sch,
									 struct gnutella_node *n)
{
	struct sent_node_data *sd = g_new(struct sent_node_data, 1);
	sd->ip = n->ip;
	sd->port = n->port;
	g_hash_table_insert(sch->sent_nodes, sd, (void *) 1);
}

void mark_search_sent_to_connected_nodes(struct search *sch)
{
	GSList *l;
	struct gnutella_node *n;

	g_hash_table_freeze(sch->sent_nodes);
	for (l = sl_nodes; l; l = l->next) {
		n = (struct gnutella_node *) l->data;
		if (NODE_IS_WRITABLE(n))
			mark_search_sent_to_node(sch, n);
	}
	g_hash_table_thaw(sch->sent_nodes);
}

/* Create and send a search request packet */

static void __search_send_packet(struct search *sch, struct gnutella_node *n)
{
	struct gnutella_msg_search *m;
	guint32 size;

	/*
	 * Don't send on a temporary connection.
	 * Although gmsg_sendto_one() is protected, it's useless to go through all
	 * the message building only to discard the message at the end.
	 * Moreover, we don't want to record the search being sent to this IP/port.
	 *		--RAM, 13/01/2002
	 */

	if (n && NODE_IS_PONGING_ONLY(n))
		return;

	size = sizeof(struct gnutella_msg_search) + strlen(sch->query) + 1;

	m = (struct gnutella_msg_search *) g_malloc(size);

	/* Use the first one on the list */
	memcpy(m->header.muid, sch->muids->data, 16);

	m->header.function = GTA_MSG_SEARCH;
	m->header.ttl = my_ttl;
	m->header.hops = hops_random_factor ? random_value(hops_random_factor) : 0;
	if (m->header.ttl + m->header.hops > hard_ttl_limit)
		m->header.ttl = hard_ttl_limit - m->header.hops;

	WRITE_GUINT32_LE(size - sizeof(struct gnutella_header),
					 m->header.size);

	WRITE_GUINT16_LE(minimum_speed, m->search.speed);

	strcpy(m->search.query, sch->query);

	message_add(m->header.muid, GTA_MSG_SEARCH, NULL);

	if (n) {
		mark_search_sent_to_node(sch, n);
		gmsg_sendto_one(n, (guchar *) m, size);
	} else {
		mark_search_sent_to_connected_nodes(sch);
		gmsg_sendto_all(sl_nodes, (guchar *) m, size);
	}

	g_free(m);
}

static void search_add_new_muid(struct search *sch)
{
	guchar *muid = (guchar *) g_malloc(16);

	generate_new_muid(muid, TRUE);

	if (sch->muids)				/* If this isn't the first muid */
		search_reset_sent_nodes(sch);
	sch->muids = g_slist_prepend(sch->muids, (gpointer) muid);
}

static void search_send_packet(struct search *sch)
{
	autodownload_init();			/* Reload patterns, if necessary */
	__search_send_packet(sch, NULL);
}

static guint search_hash_func(gconstpointer key)
{
	struct record *rc = (struct record *) key;
	/* Must use same fields as search_hash_key_compare() --RAM */
	return
		g_str_hash(rc->name) ^
		g_int_hash(&rc->size) ^
		g_int_hash(&rc->results_set->ip) ^
		g_int_hash(&rc->results_set->port) ^
		g_int_hash(&rc->results_set->guid[0]) ^
		g_int_hash(&rc->results_set->guid[4]) ^
		g_int_hash(&rc->results_set->guid[8]) ^
		g_int_hash(&rc->results_set->guid[12]);
}

static gint search_hash_key_compare(gconstpointer a, gconstpointer b)
{
	struct record *rc1 = (struct record *) a;
	struct record *rc2 = (struct record *) b;

	/* Must compare same fields as search_hash_func() --RAM */
	return rc1->size == rc2->size
		&& rc1->results_set->ip == rc2->results_set->ip
		&& rc1->results_set->port == rc2->results_set->port
		&& 0 == memcmp(rc1->results_set->guid, rc2->results_set->guid, 16)
		&& 0 == strcmp(rc1->name, rc2->name);
}


struct search *new_search(guint16 speed, gchar * query)
{
	return _new_search(speed, query, 0);
}

void search_stop(struct search *sch)
{
	if (sch->passive) {
		g_assert(!sch->frozen);
		sch->frozen = TRUE;
	} else {
		g_assert(sch->reissue_timeout_id);
		g_assert(sch->reissue_timeout); /* not already stopped */

		sch->reissue_timeout = 0;
		update_one_reissue_timeout(sch);

		g_assert(sch->reissue_timeout_id == 0);
	}
}

void search_resume(struct search *sch)
{
	autodownload_init();			/* Reload patterns, if necessary */
	if (sch->passive) {
		g_assert(sch->frozen);
		sch->frozen = FALSE;
	} else {
		g_assert(sch->reissue_timeout == 0);	/* already stopped */

		sch->reissue_timeout = search_reissue_timeout;
		sch->reissue_timeout_id =
			g_timeout_add(sch->reissue_timeout * 1000,
						  search_reissue_timeout_callback, sch);
	}
}

static gboolean search_already_sent_to_node(struct search *sch,
											struct gnutella_node *n)
{
	struct sent_node_data sd;
	sd.ip = n->ip;
	sd.port = n->port;
	return (gboolean) g_hash_table_lookup(sch->sent_nodes, &sd);
}

static void node_added_callback(gpointer data)
{
	struct search *sch = (struct search *) data;
	g_assert(node_added);
	g_assert(data);
	if (!search_already_sent_to_node(sch, node_added)) {
		__search_send_packet(sch, node_added);
	}
}

static guint sent_node_hash_func(gconstpointer key)
{
	struct sent_node_data *sd = (struct sent_node_data *) key;

	/* ensure that we've got sizeof(gint) bytes of deterministic data */
	gint ip = sd->ip;
	gint port = sd->port;

	return g_int_hash(&ip) ^ g_int_hash(&port);
}

static gint sent_node_compare(gconstpointer a, gconstpointer b)
{
	struct sent_node_data *sa = (struct sent_node_data *) a;
	struct sent_node_data *sb = (struct sent_node_data *) b;

	return sa->ip == sb->ip && sa->port == sb->port;
}

static gboolean search_reissue_timeout_callback(gpointer data)
{
	struct search *sch = (struct search *) data;

	if (dbg)
		printf("reissuing search %s.\n", sch->query);
	search_reissue(sch);

	return TRUE;
}

static void update_one_reissue_timeout(struct search *sch)
{
	g_source_remove(sch->reissue_timeout_id);
	if (sch->reissue_timeout > 0) {
		if (dbg > 3)
			printf("updating search %s with timeout %d.\n", sch->query,
				   sch->reissue_timeout * 1000);
		sch->reissue_timeout_id =
			g_timeout_add(sch->reissue_timeout * 1000,
						  search_reissue_timeout_callback, sch);
	} else {
		sch->reissue_timeout_id = 0;
		if (dbg)
			printf("canceling search %s reissue timeout.\n", sch->query);
	}
}

void search_update_reissue_timeout(guint32 timeout)
{
	GSList *l;

	search_reissue_timeout = timeout;

	for (l = searches; l; l = l->next) {
		struct search *sch = (struct search *) l->data;
		if (sch->passive)
			continue;
		if (sch->reissue_timeout > 0)	/* Not stopped */
			sch->reissue_timeout = timeout;
		if (sch->reissue_timeout_id)
			update_one_reissue_timeout(sch);
	}
}

/*
 * search_remove_r_set
 *
 * Remove reference to results in our search.
 * Last one to remove it will trigger a free.
 */
static void search_remove_r_set(struct search *sch, struct results_set *rs)
{
	sch->r_sets = g_slist_remove(sch->r_sets, rs);
	search_free_r_set(rs);
}


/* Start a new search */

struct search *_new_search(guint16 speed, gchar * query, guint flags)
{
	struct search *sch;
	GList *glist;

	sch = (struct search *) g_malloc0(sizeof(struct search));

	sch->query = g_strdup(query);
	sch->speed = minimum_speed;

	if (flags & SEARCH_PASSIVE) {
		sch->passive = 1;
		search_passive++;
		autodownload_init();		/* Reload patterns, if necessary */
	} else {
		search_add_new_muid(sch);
		sch->sent_nodes =
			g_hash_table_new(sent_node_hash_func, sent_node_compare);
		search_send_packet(sch);

		sch->new_node_hook = g_hook_alloc(&node_added_hook_list);
		sch->new_node_hook->data = sch;
		sch->new_node_hook->func = node_added_callback;
		g_hook_prepend(&node_added_hook_list, sch->new_node_hook);

		sch->reissue_timeout = search_reissue_timeout;
		sch->reissue_timeout_id =
			g_timeout_add(sch->reissue_timeout * 1000,
						  search_reissue_timeout_callback, sch);
	}

	/* Create the list item */

	sch->list_item = gtk_list_item_new_with_label(sch->query);

	gtk_widget_show(sch->list_item);

	glist = g_list_prepend(NULL, (gpointer) sch->list_item);

	gtk_list_prepend_items(GTK_LIST(GTK_COMBO(combo_searches)->list),
						   glist);

	/* Create a new CList if needed, or use the default CList */

	if (searches) {
		/* We have to create a new clist for this search */
		gui_search_create_clist(&sch->scrolled_window, &sch->clist);

		gtk_object_set_user_data((GtkObject *) sch->scrolled_window,
								 (gpointer) sch);

		gtk_notebook_append_page(GTK_NOTEBOOK(notebook_search_results),
								 sch->scrolled_window, NULL);

		gtk_notebook_set_page(GTK_NOTEBOOK(notebook_search_results),
							  gtk_notebook_page_num(GTK_NOTEBOOK
													(notebook_search_results),
													sch->scrolled_window));
	} else {
		/* There are no searches currently, we can use the default clist */

		if (default_scrolled_window && default_search_clist) {
			sch->scrolled_window = default_scrolled_window;
			sch->clist = default_search_clist;

			default_search_clist = default_scrolled_window = NULL;
		} else
			g_warning
				("new_search(): No current search but no default clist !?\n");

		gtk_object_set_user_data((GtkObject *) sch->scrolled_window,
								 (gpointer) sch);
	}

	gui_search_update_tab_label(sch);
	sch->tab_updating = gtk_timeout_add(tab_update_time * 1000,
										(GtkFunction)
										gui_search_update_tab_label, sch);

	sch->dups =
		g_hash_table_new(search_hash_func, search_hash_key_compare);
	if (!sch->dups)
		g_error("new_search: unable to allocate hash table.\n");

	if (!searches && search_results_show_tabs)
		gtk_notebook_set_show_tabs(GTK_NOTEBOOK(notebook_search_results),
								   TRUE);

	gtk_signal_connect(GTK_OBJECT(sch->list_item), "select",
					   GTK_SIGNAL_FUNC(on_search_selected),
					   (gpointer) sch);

	on_search_switch(sch);

	gtk_widget_set_sensitive(combo_searches, TRUE);
	gtk_widget_set_sensitive(button_search_close, TRUE);

	gtk_entry_set_text(GTK_ENTRY(entry_search), "");

	searches = g_slist_append(searches, (gpointer) sch);

	filters_new_search(sch);


	return sch;
}

/* Searches results */

gint search_compare(gint sort_col, struct record * r1, struct record * r2)
{
	struct results_set *rs1 = r1->results_set;
	struct results_set *rs2 = r2->results_set;

	switch (sort_col) {
	case 0:		/* File */
		return strcmp(r1->name, r2->name);
	case 1:		/* Size */
		return
			(r1->size == r2->size) ? 0 :
			(r1->size > r2->size) ? +1 : -1;
	case 2:		/* Speed */
		return
			(rs1->speed == rs2->speed) ? 0 :
			(rs1->speed > rs2->speed) ? +1 : -1;
	case 3:		/* Host */
		return
			(rs1->ip == rs2->ip) ?  (gint) rs1->port - (gint) rs2->port :
			(rs1->ip > rs2->ip) ? +1 : -1;
	case 4:		/* Info */
		return
			(rs1->trailer && rs2->trailer) ?
				strcmp(rs1->trailer, rs2->trailer) :
				rs1->trailer ? +1 : -1;
	}
	return 0;
}

/*
 * extract_vendor_name
 *
 * Extract vendor name from the results set's trailer, and return the name.
 * If no trailer, or if we can't understand the name, return NULL.
 * Otherwise returns the name as a pointer to static data.
 *
 * As a side effect, set the ST_KNOWN_VENDOR in the status flags when the
 * vendor is known.
 */
static gchar *extract_vendor_name(struct results_set * rs)
{
	static gchar temp[5];
	gchar *vendor = NULL;
	guint32 t;
	gint i;

	if (!rs->trailer)
		return NULL;

	READ_GUINT32_BE(rs->trailer, t);
	rs->status |= ST_KNOWN_VENDOR;

	switch (t) {
	case T_BEAR: vendor = "Bear";			break;
	case T_CULT: vendor = "Cultiv8r";		break;
	case T_FIRE: vendor = "FireFly";		break;
	case T_FISH: vendor = "PEERahna";		break;
	case T_GNEW: vendor = "Gnewtellium";	break;
	case T_GNOT: vendor = "Gnotella";		break;
	case T_GNUC: vendor = "Gnucleus";		break;
	case T_GNUT: vendor = "Gnut";			break;
	case T_GTKG: vendor = "Gtk-Gnut";		break;
	case T_HSLG: vendor = "Hagelslag";		break;
	case T_LIME: vendor = "Lime";			break;
	case T_MACT: vendor = "Mactella";		break;
	case T_MNAP: vendor = "MyNapster";		break;
	case T_MRPH: vendor = "Morpheus";		break;
	case T_MUTE: vendor = "Mutella";		break;
	case T_NAPS: vendor = "NapShare";		break;
	case T_OCFG: vendor = "OpenCola";		break;
	case T_OPRA: vendor = "Opera";			break;
	case T_PHEX: vendor = "Phex";			break;
	case T_QTEL: vendor = "Qtella";			break;
	case T_SNUT: vendor = "SwapNut";		break;
	case T_SWAP: vendor = "Swapper";		break;
	case T_TOAD: vendor = "ToadNode";		break;
	case T_XOLO: vendor = "Xolox";			break;
	case T_XTLA: vendor = "Xtella";			break;
	case T_ZIGA: vendor = "Ziga";			break;
	default:
		/* Unknown type, look whether we have all alphanum */
		rs->status &= ~ST_KNOWN_VENDOR;
		for (i = 0; i < 4; i++) {
			if (isalpha(rs->trailer[i]))
				temp[i] = rs->trailer[i];
			else {
				temp[0] = 0;
				break;
			}
		}
		temp[4] = 0;
		vendor = temp[0] ? temp : NULL;
		break;
	}

	return vendor;
}

/*
 * get_results_set
 *
 * Parse Query Hit and extract the embedded records, plus the optional
 * trailing Query Hit Descritor (QHD).
 *
 * Returns a structure describing the whole result set, or NULL if we
 * were unable to parse it properly.
 */
static struct results_set *get_results_set(struct gnutella_node *n)
{
	struct results_set *rs;
	struct record *rc;
	gchar *e, *s, *fname, *tag;
	guint32 nr, size, index, taglen;
	struct gnutella_search_results *r;

	/* We shall try to detect malformed packets as best as we can */
	if (n->size < 27) {
		/* packet too small 11 header, 16 GUID min */
		g_warning("get_results_set(): given too small a packet (%d bytes)",
				  n->size);
		return NULL;
	}

	rs = (struct results_set *) g_malloc0(sizeof(struct results_set));
	r = (struct gnutella_search_results *) n->data;

	/* Transfer the Query Hit info to our internal results_set struct */

	rs->num_recs = (guint8) r->num_recs;		/* Number of hits */
	READ_GUINT32_BE(r->host_ip, rs->ip);		/* IP address */
	READ_GUINT16_LE(r->host_port, rs->port);	/* Port */
	READ_GUINT32_LE(r->host_speed, rs->speed);	/* Connection speed */

	/* Now come the result set, and the servent ID will close the packet */

	s = r->records;				/* Start of the records */
	e = s + n->size - 11 - 16;	/* End of the records, less header, GUID */
	nr = 0;

	if (dbg > 7)
		dump_hex(stdout, "Query Hit Data", n->data, n->size);

	while (s < e && nr < rs->num_recs) {
		READ_GUINT32_LE(s, index);
		s += 4;					/* File Index */
		READ_GUINT32_LE(s, size);
		s += 4;					/* File Size */

		/* Followed by file name, and termination (double NUL) */
		fname = s;
		tag = NULL;

		while (s < e && *s)
			s++;				/* move s up to the next double NUL */
		if (s >= e)
			goto bad_packet;

		/*
		 * `s' point to the first NUL of the double NUL sequence.
		 *
		 * Between the two NULs at the end of each record, servents may put
		 * some extra information about the file (a tag), but this information
		 * may not contain any NUL.	If it does, it needs encoding (e.g.
		 * base64), but if it's ASCII, then it's ok to put it as-is.
		 */

		if (s[1]) {
			guint tagbin = 0;

			/* Not a NUL, so we're *probably* within the tag info */

			s++;				/* Skip first NUL */
			tag = s;
			taglen = 0;

			/*
			 * Inspect the tag, and if we see too many binary (non-ASCII),
			 * then forget about it, it's coded garbage.
			 *				--RAM, 10/09/2001
			 */

			while (s < e) {		/* On the way to second NUL */
				gchar c = *s;
				if (!c)
					break;		/* Reached second nul */
				s++;
				taglen++;
				if (!isalpha(c))
					tagbin++;
			}

			if (s >= e)
				goto bad_packet;

			if (3 * tagbin >= taglen)	/* More than 1/3 of binary */
				tag = NULL;		/* Discard tag */

			s++;				/* Now points to next record */
		} else
			s += 2;				/* Skip double NUL */

		/* Okay, one more record */

		nr++;

		rc = (struct record *) g_malloc0(sizeof(struct record));
		rc->index = index;
		rc->size = size;
		rc->name = g_strdup(fname);
		rc->tag = tag ? g_strdup(tag) : NULL;

		rc->results_set = rs;
		rs->records = g_slist_prepend(rs->records, (gpointer) rc);
	}

	/*
	 * If we have not reached the end of the packet, then we have a trailer.
	 * It can be of any length, but bound by the maximum query hit packet
	 * size we configured for this node.
	 *
	 * The payload of the trailer is vendor-specific, but its "header" is
	 * somehow codified:
	 *
	 *	bytes 0..3: vendor code (4 letters)
	 *	byte 4	: open data size
	 *
	 * Followed by open data (flags usually), and opaque data.
	 */

	if (s < e) {
		guint32 tlen = e - s;
		rs->trailer_len = tlen;
		rs->trailer = g_malloc0(tlen);
		memcpy(rs->trailer, s, tlen);	/* Copy whole trailer */
	}

	if (nr != rs->num_recs)
		goto bad_packet;

	/* We now have the guid of the node */

	memcpy(rs->guid, e, 16);

	/*
	 * Compute status bits, decompile trailer info, if present
	 */

	if (rs->trailer) {
		gchar *vendor = extract_vendor_name(rs);
		guint32 t;

		READ_GUINT32_BE(rs->trailer, t);

		switch (t) {
		case T_NAPS:
			/*
			 * NapShare has a one-byte only flag: no enabler, just setters.
			 *		--RAM, 17/12/2001
			 */
			if (rs->trailer[4] == 1) {
				if (rs->trailer[5] & 0x04) rs->status |= ST_BUSY;
				if (rs->trailer[5] & 0x01) rs->status |= ST_FIREWALL;
				rs->status |= ST_PARSED_TRAILER;
			}
			break;
		case T_LIME:
			if (rs->trailer[4] == 4)
				rs->trailer[4] = 2;		/* We ignore XML data size */
				/* Fall through */
		case T_FIRE:
		case T_FISH:
		case T_GTKG:
		case T_BEAR:
		case T_GNOT:
		case T_GNUC:
		case T_SNUT:
		default:
			if (rs->trailer[4] == 2) {
				guint32 status =
					((guint32) rs->trailer[5]) & ((guint32) rs-> trailer[6]);
				if (status & 0x04) rs->status |= ST_BUSY;
				if (status & 0x01) rs->status |= ST_FIREWALL;
				if (status & 0x08) rs->status |= ST_UPLOADED;
				rs->status |= ST_PARSED_TRAILER;
			} else if (rs->status  & ST_KNOWN_VENDOR)
				g_warning("vendor %s changed # of open data bytes to %d",
						  vendor, rs->trailer[4]);
			else if (vendor)
				g_warning("ignoring %d open data byte%s from unknown vendor %s",
					rs->trailer[4], rs->trailer[4] == 1 ? "" : "s", vendor);
			break;
		}
	}

	return rs;

	/*
	 * Come here when we encounter bad packets (NUL chars not where expected,
	 * or missing).	The whole packet is ignored.
	 *				--RAM, 09/01/2001
	 */

  bad_packet:
	g_warning
		("Bad Query Hit packet from %s, ignored (%u/%u records parsed)\n",
		 node_ip(n), nr, rs->num_recs);
	search_free_r_set(rs);
	return NULL;				/* Forget set, comes from a bad node */
}

/*
 * search_result_is_dup
 *
 * Check to see whether we already have a record for this file.
 * If we do, make sure that the index is still accurate,
 * otherwise inform the interested parties about the change.
 *
 * Returns true if the record is a duplicate.
 */
gboolean search_result_is_dup(struct search * sch, struct record * rc)
{
	struct record *old_rc;
	gpointer dummy;
	gboolean found;

	found = g_hash_table_lookup_extended(sch->dups, rc,
		(gpointer *) &old_rc, &dummy);

	if (!found)
		return FALSE;

	/*
	 * Actually, if the index is the only thing that changed,
	 * we want to overwrite the old one (and if we've
	 * got the download queue'd, replace it there too.
	 *		--RAM, 17/12/2001 from a patch by Vladimir Klebanov
	 *
	 * XXX needs more care: handle is_old, and use GUID for patching.
	 * XXX the client may change its GUID as well, and this must only
	 * XXX be used in the hash table where we record which downloads are
	 * XXX queued from whom.
	 * XXX when the GUID changes for a download in push mode, we have to
	 * XXX change it.  We have a new route anyway, since we just got a match!
	 */

	if (rc->index != old_rc->index) {
		g_warning("Index changed from %u to %u at %s for %s",
			old_rc->index, rc->index, guid_hex_str(rc->results_set->guid),
			rc->name);
		download_index_changed(
			rc->results_set->ip,		/* This is for optimizing lookups */
			rc->results_set->port,
			rc->results_set->guid,		/* This is for formal identification */
			old_rc->index,
			rc->index);
		old_rc->index = rc->index;
	}

	return TRUE;		/* yes, it's a duplicate */
}

/*
 * search_gui_update
 *
 * Update the search GUI window by displaying only those records from the
 * result set that pass our filtering criteria.
 */
static void search_gui_update(struct search *sch, struct results_set *rs)
{
	gchar *titles[5];
    GSList* next;
    GSList* l;
	guint32 row;
	GString *vinfo = g_string_sized_new(40);
	GString *info = g_string_sized_new(80);
	gchar *vendor;
	gboolean need_push;			/* Would need a push to get this file? */
	gboolean skip_records;		/* Shall we skip those records? */
	extern gboolean is_firewalled;

	vendor = extract_vendor_name(rs);

	if (vendor)
		g_string_append(vinfo, vendor);

	if (rs->status & ST_BUSY)
		g_string_append(vinfo, ", busy");
	if (rs->status & ST_UPLOADED)
		g_string_append(vinfo, ", stable");	/* Allows uploads -> stable */
	if (rs->status & ST_FIREWALL)
		g_string_append(vinfo, ", push");
	if (vendor && !(rs->status & ST_PARSED_TRAILER)) {
		g_string_append(vinfo, ", <unparsed>");
	}

	/*
	 * Update the GUI
	 */

	gtk_clist_freeze(GTK_CLIST(sch->clist));

	/*
	 * If we're firewalled, or they don't want to send pushes, then don't
	 * bother displaying results if they need a push request to succeed.
	 *		--RAM, 10/03/2002
	 */

	need_push = (rs->status & ST_FIREWALL) ||
		!check_valid_host(rs->ip, rs->port);
	skip_records = (!send_pushes || is_firewalled) && need_push;

	for (l = rs->records; l; l = next) {
		struct record *rc = (struct record *) l->data;
		next = l->next;

        if (dbg > 7)
            printf("search_gui_update: adding %s (%s)\n",
				rc->name, vinfo->str);

		/*
		 * If we have too many results in this search already,
		 * or if the size is zero bytes,
		 * or we don't send pushes and it's a private IP,
		 * or if this is a duplicate search result,
		 * or if we are filtering this result, throw the record away.
		 *
		 * Note that we pass ALL records through search_result_is_dup(), to
		 * be able to update the index/GUID of our records correctly, when
		 * we detect a change.
		 */

		if (
			search_result_is_dup(sch, rc)    ||
			skip_records                     ||
			sch->items >= search_max_results ||
			rc->size == 0                    ||
			!filter_record(sch, rc)
		)
			continue;

		sch->items++;
		g_hash_table_insert(sch->dups, rc, (void *) 1);
		rc->refcount++;

		titles[0] = rc->name;
		titles[1] = short_size(rc->size);
		g_snprintf(stmp_2, sizeof(stmp_2), "%u", rs->speed);
		titles[2] = stmp_2;
		titles[3] = ip_port_to_gchar(rs->ip, rs->port);

		if (rc->tag) {
			guint len = strlen(rc->tag);
			if (len > MAX_TAG_SHOWN) {
				/*
				 * We want to limit the length of the tag shown, but we don't
				 * want to loose that information.	I imagine to have a popup
				 * "show file info" one day that will give out all the
				 * information.
				 *				--RAM, 09/09/2001
				 */

				gchar saved = rc->tag[MAX_TAG_SHOWN];
				rc->tag[MAX_TAG_SHOWN] = '\0';
				g_string_append(info, rc->tag);
				rc->tag[MAX_TAG_SHOWN] = saved;
			} else
				g_string_append(info, rc->tag);
		}
		if (vinfo->len) {
			if (info->len)
				g_string_append(info, "; ");
			g_string_append(info, vinfo->str);
		}
		titles[4] = info->str;

		if (!sch->sort)
			row = gtk_clist_append(GTK_CLIST(sch->clist), titles);
		else {
			/*
			 * gtk_clist_set_auto_sort() can't work for row data based sorts!
			 * Too bad.
			 * So we need to find the place to put the result by ourselves.
			 */

			GList *work;

			row = 0;

			work = GTK_CLIST(sch->clist)->row_list;

			if (sch->sort_order > 0) {
				while (row < GTK_CLIST(sch->clist)->rows &&
					   search_compare(sch->sort_col, rc,
									  (struct record *)
									  GTK_CLIST_ROW(work)->data) > 0) {
					row++;
					work = work->next;
				}
			} else {
				while (row < GTK_CLIST(sch->clist)->rows &&
					   search_compare(sch->sort_col, rc,
									  (struct record *)
									  GTK_CLIST_ROW(work)->data) < 0) {
					row++;
					work = work->next;
				}
			}

			gtk_clist_insert(GTK_CLIST(sch->clist), row, titles);

		}

		gtk_clist_set_row_data(GTK_CLIST(sch->clist), row, (gpointer) rc);
		g_string_truncate(info, 0);
	}

	gtk_clist_thaw(GTK_CLIST(sch->clist));

	g_string_free(info, TRUE);
	g_string_free(vinfo, TRUE);
}

void search_matched(struct search *sch, struct results_set *rs)
{
	guint32 old_items = sch->items;

	if (use_autodownload) {
		GSList *l;
		gboolean need_push =
			(rs->status & ST_FIREWALL) || !check_valid_host(rs->ip, rs->port);

		if (send_pushes || !need_push) {
			for (l = rs->records; l; l = l->next) {
				struct record *rc = (struct record *) l->data;

				/*
				 * We apply search filters on the entry, on the basis that
				 * if it is not to be shown, then it is not desirable.
				 * 		--RAM, 09/03/2002, after an anonymous patch
				 */

				if (rc->size == 0 || !filter_record(sch, rc))
					continue;

				/* Attempt to autodownload each result if desirable. */
				autodownload_notify(rc->name, rc->size, rc->index, rs->ip,
					rs->port, rs->guid, need_push);
			}
		}
	}

	/*
	 * We always update the GUI, even if we can determine here that we
	 * already have more items than necessary.  The reason is that we benefit
	 * from the side effect of checking all records against index changes
	 * that could affect our downloads.
	 */

	search_gui_update(sch, rs);

	/* Adds the set to the list */
	sch->r_sets = g_slist_prepend(sch->r_sets, (gpointer) rs);
	rs->refcount++;

	if (old_items == 0 && sch == current_search && sch->items > 0) {
		gtk_widget_set_sensitive(button_search_clear, TRUE);
		gtk_widget_set_sensitive(popup_search_clear_results, TRUE);
	}

	if (sch == current_search) {
		gui_search_update_items(sch);
	} else {
		sch->unseen_items += sch->items - old_items;
	}

	if (time(NULL) - sch->last_update_time < tab_update_time)
		gui_search_update_tab_label(sch);

	if (sch->reissue_timeout_id) {
		update_one_reissue_timeout(sch);
	}
}

gboolean search_has_muid(struct search *sch, guchar * muid)
{
	GSList *m;

	for (m = sch->muids; m; m = m->next)
		if (!memcmp(muid, (guchar *) m->data, 16))
			return TRUE;
	return FALSE;
}

/*
 * search_results
 *
 * This routine is called for each Query Hit packet we receive.
 */
void search_results(struct gnutella_node *n)
{
	struct results_set *rs;
	GSList *selected_searches = NULL;
	GSList *l;
	gboolean extract_vendor = FALSE;

	/*
	 * If we don't have any known vendor name yet (0.4 handshaking), then
	 * parse the query hits from that node (hops=0) to see if they have a
	 * vendor tag in the QHD.
	 *
	 * NB: route_message() increases hops by 1 for messages we handle.
	 */

	if (
		n->vendor == NULL && n->header.hops == 1 &&
		!(n->attrs & NODE_A_QHD_NO_VTAG)		/* Not known to have no tag */
	)
		extract_vendor = TRUE;

	/*
	 * Look for all the searches, and put the ones we need to possibly
	 * dispatch the results to into the selected_searches list.
	 */

	for (l = searches; l; l = l->next) {
		struct search *sch = (struct search *) l->data;

		/*
		 * Candidates are all non-frozen passive searches, and searches
		 * for which we sent a query bearing the message ID of the reply.
		 */

		if (
			(sch->passive && !sch->frozen) ||
			search_has_muid(sch, n->header.muid)
		)
			selected_searches = g_slist_append(selected_searches, sch);
	}

	/*
	 * If we don't have any selected search, we're done.
	 */

	if (selected_searches == NULL && !extract_vendor)
		return;

	/*
	 * Parse the packet.
	 */

	rs = get_results_set(n);
	if (rs == NULL)
		goto final_cleanup;

	/*
	 * Extract vendor tag if needed.
	 */

	if (extract_vendor) {
		gchar *vendor = extract_vendor_name(rs);

		if (vendor) {
			n->vendor = g_strdup(vendor);
			gui_update_node_vendor(n);
		} else
			n->attrs |= NODE_A_QHD_NO_VTAG;		/* No vendor tag in QHD */

		/*
		 * If we only parsed the results to get the tag, we're done.
		 */

		if (selected_searches == NULL) {
			search_free_r_set(rs);
			return;
		}
	}

	/*
	 * Dispatch the results to the selected searches.
	 */

	for (l = selected_searches; l; l = l->next) {
		struct search *sch = (struct search *) l->data;
		search_matched(sch, rs);
	}

	g_assert(rs->refcount > 0);

	/*
	 * Some of the records might have not been used by searches, and need
	 * to be freed.  If no more records remain, we request that the
	 * result set be removed from all the dispatched searches, the last one
	 * removing it will cause its destruction.
	 */

	search_clean_r_set(rs);

	if (rs->num_recs == 0) {
		for (l = selected_searches; l; l = l->next) {
			struct search *sch = (struct search *) l->data;
			search_remove_r_set(sch, rs);
		}
	}
		
final_cleanup:
	g_slist_free(selected_searches);
}

/*
 * search_extract_host
 *
 * Extract IP/port information out of the Query Hit into `ip' and `port'.
 */
void search_extract_host(struct gnutella_node *n, guint32 *ip, guint16 *port)
{
	guint32 hip;
	guint16 hport;
	struct gnutella_search_results *r =
		(struct gnutella_search_results *) n->data;

	/* Read Query Hit info */

	READ_GUINT32_BE(r->host_ip, hip);		/* IP address */
	READ_GUINT16_LE(r->host_port, hport);	/* Port */

	*ip = hip;
	*port = hport;
}

void search_shutdown(void)
{
	GSList *l;

	for (l = searches; l; l = l->next) {
		struct search *sch = (struct search *) l->data;
		if (!sch->passive) {
			GSList *m;
			for (m = sch->muids; m; m = m->next) {
				g_free(m->data);
			}
			g_slist_free(sch->muids);
			search_free_sent_nodes(sch);
		}
		g_hash_table_foreach(sch->dups, dec_records_refcount, NULL);
		g_hash_table_destroy(sch->dups);
		sch->dups = NULL;
		search_free_r_sets(sch);
		filters_close_search(sch);
		g_free(sch->query);
		g_free(sch);
	}

	g_slist_free(searches);
}


/* ----------------------------------------- */


static void download_selection_of_clist(GtkCList * c)
{
	struct results_set *rs;
	struct record *rc;
	gboolean need_push;
	GList *l;

	for (l = c->selection; l; l = l->next) {
		gtk_clist_set_foreground(c, (gint) l->data, 
								 &gtk_widget_get_style(GTK_WIDGET(c))->fg[GTK_STATE_ACTIVE]);
		rc = (struct record *) gtk_clist_get_row_data(c, (gint) l->data);
		rs = rc->results_set;
		need_push =
			(rs->status & ST_FIREWALL) || !check_valid_host(rs->ip, rs->port);
		download_new(rc->name, rc->size, rc->index, rs->ip, rs->port,
					 rs->guid, need_push);
	}
}


void search_download_files(void)
{
	/* Download the selected files */

	if (jump_to_downloads) {
		gtk_notebook_set_page(GTK_NOTEBOOK(notebook_main),
                NOTEBOOK_MAIN_DOWNLOADS_IDX);
        // FIXME: should convert to ctree here. Expand nodes if necessary.
		gtk_clist_select_row(GTK_CLIST(ctree_menu),
			NOTEBOOK_MAIN_DOWNLOADS_IDX, 0);
	}

	if (current_search) {
		download_selection_of_clist(GTK_CLIST(current_search->clist));
		gtk_clist_unselect_all(GTK_CLIST(current_search->clist));
	} else {
		g_warning("search_download_files(): no possible search!\n");
	}
}

/* vi: set ts=4: */
