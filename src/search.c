
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
#include "routing.h"
#include "autodownload.h"
#include "hosts.h"				/* For check_valid_host() */
#include "callbacks.h"

#define MAKE_CODE(a,b,c,d) ( \
	((guint32) (a) << 24) | \
	((guint32) (b) << 16) | \
	((guint32) (c) << 8)  | \
	((guint32) (d)))

#define T_GTKG	MAKE_CODE('G','T','K','G')
#define T_NAPS	MAKE_CODE('N','A','P','S')
#define T_LIME	MAKE_CODE('L','I','M','E')
#define T_BEAR	MAKE_CODE('B','E','A','R')
#define T_GNOT	MAKE_CODE('G','N','O','T')
#define T_GNUC	MAKE_CODE('G','N','U','C')
#define T_MACT	MAKE_CODE('M','A','C','T')
#define T_SNUT	MAKE_CODE('S','N','U','T')
#define T_TOAD	MAKE_CODE('T','O','A','D')
#define T_GNUT	MAKE_CODE('G','N','U','T')
#define T_OCFG	MAKE_CODE('O','C','F','G')
#define T_XOLO	MAKE_CODE('X','O','L','O')
#define T_CULT	MAKE_CODE('C','U','L','T')
#define T_HSLG	MAKE_CODE('H','S','L','G')
#define T_OPRA	MAKE_CODE('O','P','R','A')
#define T_QTEL	MAKE_CODE('Q','T','E','L')

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

static void search_free_r_sets(struct search *);
static void search_send_packet(struct search *);
static void search_add_new_muid(struct search *sch);
static guint sent_node_hash_func(gconstpointer key);
static gint sent_node_compare(gconstpointer a, gconstpointer b);
static void search_free_sent_nodes(struct search *sch);
static gboolean search_reissue_timeout_callback(gpointer data);
static void update_one_reissue_timeout(struct search *sch);

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

/* Free one file record */

static void search_free_record(struct record *rc)
{
	g_free(rc->name);
	if (rc->tag)
		g_free(rc->tag);
	g_free(rc);
}

/* Free one results_set */

void search_free_r_set(struct results_set *rs)
{
	GSList *m;

	for (m = rs->records; m; m = m->next)
		search_free_record((struct record *) m->data);

	if (rs->trailer)
		g_free(rs->trailer);
	g_slist_free(rs->records);
	g_free(rs);
}

/* Free all the results_set's of a search */

void search_free_r_sets(struct search *sch)
{
	GSList *l;

	g_return_if_fail(sch);

	for (l = sch->r_sets; l; l = l->next)
		search_free_r_set((struct results_set *) l->data);

	g_slist_free(sch->r_sets);
	sch->r_sets = NULL;
}

/* Close a search */

void search_close_current(void)
{
	GList *glist;
	GSList *m;
	struct search *sch = current_search;

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

	search_free_r_sets(sch);

	glist = g_list_prepend(NULL, (gpointer) sch->list_item);

	gtk_list_remove_items(GTK_LIST(GTK_COMBO(combo_searches)->list), glist);

	g_hash_table_destroy(sch->dups);
	g_free(sch->query);
	g_free(sch);

	gtk_widget_set_sensitive(combo_searches, (gboolean) searches);
	gtk_widget_set_sensitive(button_search_close, (gboolean) searches);
}

void search_free_sent_node(gpointer node, gpointer unused_value,
						   gpointer unused_user_data)
{
	g_free(node);
}

static void search_free_sent_nodes(struct search *sch)
{
	g_hash_table_foreach(sch->sent_nodes, search_free_sent_node, NULL);
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
		mark_search_sent_to_node(sch, n);
	}
	g_hash_table_thaw(sch->sent_nodes);
}

/* Create and send a search request packet */

void __search_send_packet(struct search *sch, struct gnutella_node *n)
{
	struct gnutella_msg_search *m;
	guint32 size;

	size = sizeof(struct gnutella_msg_search) + strlen(sch->query) + 1;

	m = (struct gnutella_msg_search *) g_malloc(size);

	/* Use the first one on the list */
	memcpy(m->header.muid, sch->muids->data, 16);

	m->header.function = GTA_MSG_SEARCH;
	m->header.ttl = my_ttl;
	m->header.hops = hops_random_factor ?
		(rand() % (hops_random_factor + 1)) : 0;
	if (m->header.ttl + m->header.hops > hard_ttl_limit)
		m->header.ttl = hard_ttl_limit - m->header.hops;

	WRITE_GUINT32_LE(size - sizeof(struct gnutella_header),
					 m->header.size);

	WRITE_GUINT16_LE(minimum_speed, m->search.speed);

	strcpy(m->search.query, sch->query);

	message_add(m->header.muid, GTA_MSG_SEARCH, NULL);

	if (n) {
		mark_search_sent_to_node(sch, n);
		sendto_one(n, (guchar *) m, NULL, size);
	} else {
		mark_search_sent_to_connected_nodes(sch);
		sendto_all((guchar *) m, NULL, size);
	}

	g_free(m);
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
		g_int_hash(&rc->results_set->port);
}

/* Put it back when it's needed --DW */
#if 0
static char *guid_to_str(guchar * g)
{
	static char buf[16 * 3];
	static int i, j;
	char *t = "";

	for (i = 0, j = 0; i < 16;) {
		j += sprintf(&buf[j], "%s%02x", t, g[i]);
		i++;
		t = " ";
	}
	return buf;
}
#endif

static void search_add_new_muid(struct search *sch)
{
	guchar *muid = (guchar *) g_malloc(16);

	generate_new_muid(muid);

	if (sch->muids)				/* If this isn't the first muid */
		search_reset_sent_nodes(sch);
	sch->muids = g_slist_prepend(sch->muids, (gpointer) muid);
}

gint search_hash_key_compare(gconstpointer a, gconstpointer b)
{
	struct record *this_record = (struct record *) a;
	struct record *rc = (struct record *) b;
	gboolean identical;

	/* Must compare same fields as search_hash_func() --RAM */
	identical = !strcmp(rc->name, this_record->name)
		&& rc->size == this_record->size
		&& rc->results_set->ip == this_record->results_set->ip
		&& rc->results_set->port == this_record->results_set->port;

	/*
	 * Actually, if the index is the only thing that changed,
	 * we want to overwrite the old one (and if we've
	 * got the download queue'd, replace it there too.
	 *		--RAM, 17/12/2001 from a patch by Vladimir Klebanov
	 */
	if (identical && rc->index != this_record->index) {
		g_warning("Index changed from %u to %u for %s",
			this_record->index, rc->index, rc->name);
		download_index_changed(
			this_record->results_set->ip,
			this_record->results_set->port,
			this_record->index,
			rc->index);
		this_record->index = rc->index;
		return TRUE;		/* yes, it's a duplicate */
	}

	return identical && rc->index == this_record->index;
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

struct results_set *get_results_set(struct gnutella_node *n)
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

gboolean search_result_is_dup(struct search * sch, struct record * rc)
{
	return (gboolean) g_hash_table_lookup(sch->dups, rc);
}

static void search_gui_update(struct search * sch, struct results_set * rs,
                              GString* info, GString* vinfo)
{
	gchar *titles[5];
    GSList* next;
    GSList* l;
	guint32 row;

	/* Update the GUI */

	gtk_clist_freeze(GTK_CLIST(sch->clist));

	for (l = rs->records; l; l = next) {
		struct record *rc = (struct record *) l->data;
		next = l->next;

        if (dbg > 7)
            printf("%s(): adding %s (%s)\n", __FUNCTION__,
                   rc->name, vinfo->str);

		/*
		 * If we have too many results in this search already,
		 * or if the size is zero bytes,
		 * or we don't send pushes and it's a private IP,
		 * or if this is a duplicate search result,
		 * or if we are filtering this result, throw the record away.
		 */

		if (
			sch->items >= search_max_results ||
			rc->size == 0 ||
			(!send_pushes && !check_valid_host(rs->ip, rs->port)) ||
			search_result_is_dup(sch, rc) ||
			!filter_record(sch, rc)
		) {
			rs->records = g_slist_remove(rs->records, rc);
			rs->num_recs--;
			search_free_record(rc);
			continue;
		}

		sch->items++;
		g_hash_table_insert(sch->dups, rc, (void *) 1);

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
}

void search_matched(struct search *sch, struct results_set *rs)
{
	GString *vinfo = g_string_sized_new(40);
	GString *info = g_string_sized_new(80);
	guint32 old_items = sch->items;

	/* Compute status bits, decompile trailer info, if present */

	if (rs->trailer) {
		gchar *vendor = NULL;
		guint32 t;
		gchar temp[5];
		gint i;

		READ_GUINT32_BE(rs->trailer, t);
		rs->status = ST_KNOWN_VENDOR;

		switch (t) {
		case T_GTKG: vendor = "Gtk-Gnut";		break;
		case T_NAPS: vendor = "NapShare";		break;
		case T_LIME: vendor = "Lime";			break;
		case T_BEAR: vendor = "Bear";			break;
		case T_GNOT: vendor = "Gnotella";		break;
		case T_GNUC: vendor = "Gnucleus";		break;
		case T_MACT: vendor = "Mactella";		break;
		case T_SNUT: vendor = "SwapNut";		break;
		case T_TOAD: vendor = "ToadNode";		break;
		case T_GNUT: vendor = "Gnut";			break;
		case T_OCFG: vendor = "OpenCola";		break;
		case T_XOLO: vendor = "Xolox";			break;
		case T_CULT: vendor = "Cultiv8r";		break;
		case T_HSLG: vendor = "Hagelslag";		break;
		case T_OPRA: vendor = "Opera";			break;
		case T_QTEL: vendor = "Qtella";			break;
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

		if (vendor)
			g_string_append(vinfo, vendor);

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

		if (rs->status & ST_BUSY)
			g_string_append(vinfo, ", busy");
		if (rs->status & ST_UPLOADED)
			g_string_append(vinfo, ", open");	/* Open for uploading */
		if (rs->status & ST_FIREWALL)
			g_string_append(vinfo, ", push");
		if (vendor && !(rs->status & ST_PARSED_TRAILER)) {
			g_string_append(vinfo, ", <unparsed>");
		}
	}

	if (use_autodownload) {
		GSList *l;

		if (
			send_pushes ||
			!((rs->status & ST_FIREWALL) || is_private_ip(rs->ip))
		) {
			for (l = rs->records; l; l = l->next) {
				struct record *rc = (struct record *) l->data;

				if (rc->size == 0)
					continue;

				/* Attempt to autodownload each result if desirable. */
				autodownload_notify(rc->name, rc->size, rc->index, rs->ip,
					rs->port, rs->guid);
			}
		}
	}

	/*
	 * If we have more entries than the configured maximum, don't even
	 * bother updating the GUI.
	 */

	if (sch->items >= search_max_results) {
		search_free_r_set(rs);
		return;
	}

	search_gui_update(sch, rs, info, vinfo);

	g_string_free(info, TRUE);
	g_string_free(vinfo, TRUE);

	/* If all the results were dups */
	if (rs->num_recs == 0) {
		search_free_r_set(rs);
		return;
	}

	/* Adds the set to the list */
	sch->r_sets = g_slist_prepend(sch->r_sets, (gpointer) rs);

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

void search_results(struct gnutella_node *n)
{
	struct search *sch;
	struct results_set *rs;
	GSList *l;

	/* Find the search matching the MUID */

	for (l = searches; l; l = l->next) {
		sch = (struct search *) l->data;
		if ((sch->passive && !sch->frozen) ||
			search_has_muid(sch, n->header.muid)
			) {
			/* This should eventually be replaced with some sort of
			   copy_results_set so that we don't have to repeatedly parse
			   the packet. */
			/* XXX when this is fixed, we'll need to do reference counting
			 * on the rs's, or duplicate them for each search so that we
			 * can free them.
			 */
			rs = get_results_set(n);

			if (rs == NULL) {
				g_warning
					("search_results: get_results_set returned NULL.\n");
				return;
			}

			/* The result set is ok */
			search_matched(sch, rs);
		}
	}
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
		search_free_r_sets(sch);
		g_hash_table_destroy(sch->dups);
		g_free(sch->query);
		g_free(sch);
	}

	g_slist_free(searches);
}



/* ----------------------------------------- */


void download_selection_of_clist(GtkCList * c)
{
	struct results_set *rs;
	struct record *rc;
	GList *l;

	for (l = c->selection; l; l = l->next) {
		rc = (struct record *) gtk_clist_get_row_data(c, (gint) l->data);
		rs = rc->results_set;
		download_new(rc->name, rc->size, rc->index, rs->ip, rs->port,
					 rs->guid);
	}
}


void search_download_files(void)
{
	/* Download the selected files */

	if (jump_to_downloads) {
		gtk_notebook_set_page(GTK_NOTEBOOK(notebook_main), 2);
		gtk_clist_select_row(GTK_CLIST(clist_menu), 2, 0);
	}

	if (current_search) {
		download_selection_of_clist(GTK_CLIST(current_search->clist));
		gtk_clist_unselect_all(GTK_CLIST(current_search->clist));
	} else {
		g_warning("search_download_files(): no possible search!\n");
	}
}

/* vi: set ts=4: */
