
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

static gchar stmp_1[4096];
static gchar stmp_2[4096];

GSList *searches = NULL;		/* List of search structs */

/* If no search are currently allocated */
GtkWidget *default_search_clist = NULL;
GtkWidget *default_scrolled_window = NULL;

struct search *current_search = NULL;	/*	The search currently displayed */
gboolean search_results_show_tabs = TRUE;	/* Display the notebook tabs? */
guint32 search_max_results = 5000;		/* Max items allowed in GUI results */
guint32 search_passive = 0;				/* Amount of passive searches */

static void search_free_r_sets(struct search *);
static void search_send_packet(struct search *);
static void search_update_items(struct search *);
static void search_add_new_muid(struct search *sch);
static guint sent_node_hash_func(gconstpointer key);
static gint sent_node_compare(gconstpointer a, gconstpointer b);
static void search_free_sent_nodes(struct search *sch);
static gboolean search_reissue_timeout_callback(gpointer data);
static void update_one_reissue_timeout(struct search *sch);

static gint select_all_lock = 0;

/* ----------------------------------------- */

static gint search_results_compare_size(GtkCList * clist, gconstpointer ptr1,
								 gconstpointer ptr2)
{
	guint32 s1 = ((struct record *) ((GtkCListRow *) ptr1)->data)->size;
	guint32 s2 = ((struct record *) ((GtkCListRow *) ptr2)->data)->size;

	return (s1 == s2) ? 0 :
		(s1 > s2) ? +1 : -1;
}

static gint search_results_compare_speed(GtkCList * clist, gconstpointer ptr1,
								  gconstpointer ptr2)
{
	struct results_set *rs1 =
		((struct record *) ((GtkCListRow *) ptr1)->data)->results_set;
	struct results_set *rs2 =
		((struct record *) ((GtkCListRow *) ptr2)->data)->results_set;

	return (rs1->speed == rs2->speed) ? 0 :
		(rs1->speed > rs2->speed) ? +1 : -1;
}

static gint search_results_compare_host(GtkCList * clist, gconstpointer ptr1,
							   gconstpointer ptr2)
{
	struct results_set *rs1 =
		((struct record *) ((GtkCListRow *) ptr1)->data)->results_set;
	struct results_set *rs2 =
		((struct record *) ((GtkCListRow *) ptr2)->data)->results_set;

	if (rs1->ip == rs2->ip)
		return (gint) rs1->port - (gint) rs2->port;
	else
		return (rs1->ip > rs2->ip) ? +1 : -1;
}

/* ----------------------------------------- */

/* Row selected */

void on_clist_search_results_select_row(GtkCList * clist, gint row,
										gint column, GdkEvent * event,
										gpointer user_data)
{
	gtk_widget_set_sensitive(button_search_download, TRUE);

	if (search_pick_all) {		// config setting select all is on
		if (!select_all_lock) {
			struct record *rc, *rc2;
			gint x, i;
			// this will be called for each selection, so only do it here
			select_all_lock = 1;
			rc = (struct record *) gtk_clist_get_row_data(clist, row);
			x = 1;
			for (i = 0; i < clist->rows; i++) {
				if (i == row)
					continue;	// skip this one
				rc2 = (struct record *) gtk_clist_get_row_data(clist, i);
				// if name match and file is same or larger, select it
				if (rc2)
					if (!strcmp(rc2->name, rc->name)) {
						if (rc2->size >= rc->size) {
							gtk_clist_select_row(clist, i, 0);
							x++;
						}
					}
			}
			g_snprintf(stmp_1, sizeof(stmp_1),
					   "		(%d auto selected)", x);
			gtk_label_set(GTK_LABEL(label_left), stmp_1);
			select_all_lock = 0;		// we are done, un "lock" it
		}
	}
}

/* Row unselected */

void on_clist_search_results_unselect_row(GtkCList * clist, gint row,
										  gint column, GdkEvent * event,
										  gpointer user_data)
{
	gboolean sensitive;

	sensitive = current_search
		&& GTK_CLIST(current_search->clist)->selection;
	gtk_widget_set_sensitive(button_search_download, sensitive);
	if (search_pick_all)
		gtk_label_set(GTK_LABEL(label_left), "");
}

/* Column title clicked */

void on_clist_search_results_click_column(GtkCList * clist, gint column,
										  gpointer user_data)
{
	if (current_search == NULL)
		return;

	switch (column) {
	case 1:		/* Size */
		gtk_clist_set_compare_func(GTK_CLIST(current_search->clist),
								   search_results_compare_size);
		break;
	case 2:		/* Speed */
		gtk_clist_set_compare_func(GTK_CLIST(current_search->clist),
								   search_results_compare_speed);
		break;
	case 3:		/* Host */
		gtk_clist_set_compare_func(GTK_CLIST(current_search->clist),
								   search_results_compare_host);
		break;
	default:
		gtk_clist_set_compare_func(GTK_CLIST(current_search->clist), NULL);
	}

	if (column == current_search->sort_col) {
		current_search->sort_order =
			(current_search->sort_order > 0) ? -1 : 1;
	} else {
		current_search->sort_col = column;
		current_search->sort_order = 1;
	}

	gtk_clist_set_sort_type(GTK_CLIST(current_search->clist),
		(current_search->sort_order > 0) ?
			GTK_SORT_ASCENDING : GTK_SORT_DESCENDING);
	gtk_clist_set_sort_column(GTK_CLIST(current_search->clist), column);

	gtk_clist_sort(GTK_CLIST(current_search->clist));

	current_search->sort = TRUE;
}

/* Search results popup menu (glade puts funcs prototypes in callbacks.h) */

void on_popup_search_stop_sorting_activate(GtkMenuItem * menuitem,
										   gpointer user_data)
{
	if (current_search)
		current_search->sort = FALSE;
}

void on_popup_search_filters_activate(GtkMenuItem * menuitem,
									  gpointer user_data)
{
	filters_open_dialog();
}

void on_popup_search_close_activate(GtkMenuItem * menuitem,
									gpointer user_data)
{
	if (current_search)
		search_close_current();
}

void on_popup_search_toggle_tabs_activate(GtkMenuItem * menuitem,
										  gpointer user_data)
{
	gtk_notebook_set_show_tabs(GTK_NOTEBOOK(notebook_search_results),
		(search_results_show_tabs = !search_results_show_tabs));
}

static void search_reissue(struct search *sch)
{
	search_add_new_muid(sch);
	search_send_packet(sch);
	update_one_reissue_timeout(sch);
}

static void search_restart(struct search *sch)
{
	search_reissue(sch);
	gtk_clist_clear(GTK_CLIST(sch->clist));
	sch->items = sch->unseen_items = 0;
	search_update_items(sch);
}

void on_popup_search_restart_activate(GtkMenuItem * menuitem,
									  gpointer user_data)
{
	if (current_search)
		search_restart(current_search);
}

void on_popup_search_duplicate_activate(GtkMenuItem * menuitem,
										gpointer user_data)
{
	if (current_search)
		new_search(current_search->speed, current_search->query);
}

void on_popup_search_stop_activate(GtkMenuItem * menuitem,
								   gpointer user_data)
{
	if (current_search) {
		gtk_widget_set_sensitive(popup_search_stop, FALSE);
		gtk_widget_set_sensitive(popup_search_resume, TRUE);
		search_stop(current_search);
	}
}

void on_popup_search_resume_activate(GtkMenuItem * menuitem,
									 gpointer user_data)
{
	if (current_search) {
		gtk_widget_set_sensitive(popup_search_stop, TRUE);
		gtk_widget_set_sensitive(popup_search_resume, FALSE);
		search_resume(current_search);
	}
}

gboolean on_clist_search_results_button_press_event(GtkWidget * widget,
													GdkEventButton * event,
													gpointer user_data)
{
	if (event->button != 3)
		return FALSE;

	gtk_widget_set_sensitive(popup_search_toggle_tabs,
							 (gboolean) searches);
	gtk_widget_set_sensitive(popup_search_close, (gboolean) searches);
	gtk_widget_set_sensitive(popup_search_restart, (gboolean) searches);
	gtk_widget_set_sensitive(popup_search_duplicate, (gboolean) searches);

	if (current_search) {
		gtk_clist_unselect_all(GTK_CLIST(current_search->clist));
		gtk_widget_set_sensitive(popup_search_stop_sorting,
								 current_search->sort);
		gtk_widget_set_sensitive(popup_search_stop,
								 current_search->
								 passive ? !current_search->
								 frozen : current_search->reissue_timeout);
		gtk_widget_set_sensitive(popup_search_resume,
								 current_search->passive ? current_search->
								 frozen : !current_search->
								 reissue_timeout);
		if (current_search->passive)
			gtk_widget_set_sensitive(popup_search_restart, FALSE);
		g_snprintf(stmp_1, sizeof(stmp_1), "%s", current_search->query);
	} else {
		gtk_widget_set_sensitive(popup_search_stop_sorting, FALSE);
		gtk_widget_set_sensitive(popup_search_stop, FALSE);
		gtk_widget_set_sensitive(popup_search_resume, FALSE);
		g_snprintf(stmp_1, sizeof(stmp_1), "No current search");
	}

	gtk_label_set(GTK_LABEL
				  ((GTK_MENU_ITEM(popup_search_title)->item.bin.child)),
				  stmp_1);

	g_snprintf(stmp_1, sizeof(stmp_1),
			   (search_results_show_tabs) ? "Hide tabs" : "Show tabs");

	gtk_label_set(GTK_LABEL
				  ((GTK_MENU_ITEM(popup_search_toggle_tabs)->item.bin.
					child)), stmp_1);

	gtk_menu_popup(GTK_MENU(popup_search), NULL, NULL, NULL, NULL, 3, 0);

	return TRUE;
}

/* Column resize */

void on_clist_search_results_resize_column(GtkCList * clist, gint column,
										   gint width, gpointer user_data)
{
	static gboolean resizing = FALSE;
	GSList *l;

	if (resizing)
		return;

	resizing = TRUE;

	search_results_col_widths[column] = width;

	for (l = searches; l; l = l->next)
		gtk_clist_set_column_width(GTK_CLIST
								   (((struct search *) l->data)->clist),
								   column, width);

	resizing = FALSE;
}

/* Create a new GtkCList for search results */

void search_create_clist(GtkWidget ** sw, GtkWidget ** clist)
{
	GtkWidget *label;
	gint i;

	*sw = gtk_scrolled_window_new(NULL, NULL);

	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(*sw),
								   GTK_POLICY_AUTOMATIC,
								   GTK_POLICY_AUTOMATIC);

	*clist = gtk_clist_new(5);

	gtk_container_add(GTK_CONTAINER(*sw), *clist);
	for (i = 0; i < 5; i++)
		gtk_clist_set_column_width(GTK_CLIST(*clist), i,
								   search_results_col_widths[i]);
	gtk_clist_set_selection_mode(GTK_CLIST(*clist),
								 GTK_SELECTION_EXTENDED);
	gtk_clist_column_titles_show(GTK_CLIST(*clist));

	label = gtk_label_new("File");
	gtk_clist_set_column_widget(GTK_CLIST(*clist), 0, label);

	label = gtk_label_new("Size");
	gtk_clist_set_column_widget(GTK_CLIST(*clist), 1, label);

	label = gtk_label_new("Speed");
	gtk_widget_show(label);
	gtk_clist_set_column_widget(GTK_CLIST(*clist), 2, label);

	label = gtk_label_new("Host");
	gtk_clist_set_column_widget(GTK_CLIST(*clist), 3, label);

	label = gtk_label_new("Info");
	gtk_clist_set_column_widget(GTK_CLIST(*clist), 4, label);

	gtk_widget_show_all(*sw);

	gtk_signal_connect(GTK_OBJECT(*clist), "select_row",
					   GTK_SIGNAL_FUNC(on_clist_search_results_select_row),
					   NULL);
	gtk_signal_connect(GTK_OBJECT(*clist), "unselect_row",
					   GTK_SIGNAL_FUNC
					   (on_clist_search_results_unselect_row), NULL);
	gtk_signal_connect(GTK_OBJECT(*clist), "click_column",
					   GTK_SIGNAL_FUNC
					   (on_clist_search_results_click_column), NULL);
	gtk_signal_connect(GTK_OBJECT(*clist), "button_press_event",
					   GTK_SIGNAL_FUNC
					   (on_clist_search_results_button_press_event), NULL);
	gtk_signal_connect(GTK_OBJECT(*clist), "resize-column",
					   GTK_SIGNAL_FUNC
					   (on_clist_search_results_resize_column), NULL);
}

void search_update_items(struct search *sch)
{
	if (sch && sch->items)
		g_snprintf(stmp_1, sizeof(stmp_1), "%u item%s found", sch->items,
				   (sch->items > 1) ? "s" : "");
	else
		g_snprintf(stmp_1, sizeof(stmp_1), "No item found");
	gtk_label_set(GTK_LABEL(label_items_found), stmp_1);
}

struct search *search_selected = NULL;

void on_search_selected(GtkItem * i, gpointer data)
{
	search_selected = (struct search *) data;
}

gboolean updating = FALSE;

/* Like search_update_tab_label but always update the label */
void __search_update_tab_label(struct search *sch)
{
	if (sch == current_search || sch->unseen_items == 0)
		g_snprintf(stmp_1, sizeof(stmp_1), "%s\n(%d)", sch->query,
				   sch->items);
	else
		g_snprintf(stmp_1, sizeof(stmp_1), "%s\n(%d, %d)", sch->query,
				   sch->items, sch->unseen_items);
	sch->last_update_items = sch->items;
	gtk_notebook_set_tab_label_text(GTK_NOTEBOOK(notebook_search_results),
									sch->scrolled_window, stmp_1);
	sch->last_update_time = time(NULL);
}

/* Doesn't update the label if nothing's changed or if the last update was
   recent. */
gboolean search_update_tab_label(struct search *sch)
{
	if (sch->items == sch->last_update_items)
		return TRUE;

	if (time(NULL) - sch->last_update_time < tab_update_time)
		return TRUE;

	__search_update_tab_label(sch);

	return TRUE;
}

void on_search_switch(struct search *sch)
{
	struct search *old_sch = current_search;
	g_return_if_fail(sch);

	current_search = sch;
	sch->unseen_items = 0;

	if (old_sch)
		__search_update_tab_label(old_sch);
	__search_update_tab_label(sch);

	search_update_items(sch);
	gui_update_minimum_speed(sch->speed);
	gtk_widget_set_sensitive(button_search_download,
							 (gboolean) GTK_CLIST(sch->clist)->selection);

	if (sch->items == 0) {
		gtk_widget_set_sensitive(button_search_clear, FALSE);
		gtk_widget_set_sensitive(popup_search_clear_results, FALSE);
	} else {
		gtk_widget_set_sensitive(button_search_clear, TRUE);
		gtk_widget_set_sensitive(popup_search_clear_results, TRUE);
	}

	gtk_widget_set_sensitive(popup_search_restart, !sch->passive);
	gtk_widget_set_sensitive(popup_search_duplicate, !sch->passive);
	gtk_widget_set_sensitive(popup_search_stop, sch->passive ?
							 !sch->frozen : sch->reissue_timeout);
	gtk_widget_set_sensitive(popup_search_resume, sch->passive ?
							 sch->frozen : sch->reissue_timeout);
}

void on_search_popdown_switch(GtkWidget * w, gpointer data)
{
	struct search *sch = search_selected;
	if (!sch || updating)
		return;
	updating = TRUE;
	on_search_switch(sch);
	gtk_notebook_set_page(GTK_NOTEBOOK(notebook_search_results),
						  gtk_notebook_page_num(GTK_NOTEBOOK
												(notebook_search_results),
												sch->scrolled_window));
	updating = FALSE;
}

void on_search_notebook_switch(GtkNotebook * notebook,
							   GtkNotebookPage * page, gint page_num,
							   gpointer user_data)
{
	struct search *sch =
		gtk_object_get_user_data((GtkObject *) page->child);
	g_return_if_fail(sch);
	if (updating)
		return;
	updating = TRUE;
	on_search_switch(sch);
	gtk_list_item_select(GTK_LIST_ITEM(sch->list_item));
	updating = FALSE;
}

/* */

void search_init(void)
{
	search_create_clist(&default_scrolled_window, &default_search_clist);
	gtk_notebook_remove_page(GTK_NOTEBOOK(notebook_search_results), 0);
	gtk_notebook_set_scrollable(GTK_NOTEBOOK(notebook_search_results),
								TRUE);
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook_search_results),
							 default_scrolled_window, NULL);
	gtk_signal_connect(GTK_OBJECT(GTK_COMBO(combo_searches)->popwin),
					   "hide", GTK_SIGNAL_FUNC(on_search_popdown_switch),
					   NULL);
	gtk_signal_connect(GTK_OBJECT(notebook_search_results), "switch_page",
					   GTK_SIGNAL_FUNC(on_search_notebook_switch), NULL);
	dialog_filters = create_dialog_filters();
	gtk_window_set_position(GTK_WINDOW(dialog_filters),
							GTK_WIN_POS_CENTER);
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

		search_update_items(NULL);

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
		g_int_hash(&rc->index) ^
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

	/* Must compare same fields as search_hash_func() --RAM */
	return !strcmp(rc->name, this_record->name)
		&& rc->index == this_record->index
		/*
		 * Actually, if the index is the only thing that changed,
		 * we probably want to overwrite the old one (and if we've
		 * got the download queue'd, replace it there too.
		 */
		&& rc->size == this_record->size
		&& rc->results_set->ip == this_record->results_set->ip
		&& rc->results_set->port == this_record->results_set->port;
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
		search_create_clist(&sch->scrolled_window, &sch->clist);

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

	search_update_tab_label(sch);
	sch->tab_updating = gtk_timeout_add(tab_update_time * 1000,
										(GtkFunction)
										search_update_tab_label, sch);

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
		debug_show_hex("Query Hit Data", n->data, n->size);

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
		 * or if this is a duplicate search result,
		 * or if we are filtering this result, throw the record away.
		 */

		if (
			sch->items >= search_max_results ||
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
			 * The author of NapShare apparently did not understand the
			 * purpose of having two flag bytes: one enabler and one
			 * setter. His trailer therefore needs to be specially parsed.
			 *				--RAM, 09/09/2001
			 */
			if ((rs->trailer[4] == 1)) {
				if (rs->trailer[5] & 0x04) rs->status |= ST_BUSY;
				if (rs->trailer[5] & 0x01) rs->status |= ST_FIREWALL;
				rs->status |= ST_PARSED_TRAILER;
			}
			break;
		case T_GTKG:
		case T_LIME:
		case T_BEAR:
		case T_GNOT:
		case T_GNUC:
		case T_SNUT:
			if ((rs->trailer[4] == 2)) {
				guint32 status =
					((guint32) rs->trailer[5]) & ((guint32) rs-> trailer[6]);
				if (status & 0x04) rs->status |= ST_BUSY;
				if (status & 0x01) rs->status |= ST_FIREWALL;
				if (status & 0x08) rs->status |= ST_UPLOADED;
				rs->status |= ST_PARSED_TRAILER;
			} else
				g_warning("vendor %s changed # of open data bytes to %d",
						  vendor, rs->trailer[4]);
			break;
		default:
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
		search_update_items(sch);
	} else {
		sch->unseen_items += sch->items - old_items;
	}

	if (time(NULL) - sch->last_update_time < tab_update_time)
		search_update_tab_label(sch);

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


void search_clear_results(void)
{
	gtk_clist_clear(GTK_CLIST(current_search->clist));
	current_search->items = current_search->unseen_items = 0;
	__search_update_tab_label(current_search);
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

void on_button_search_clear_clicked(GtkButton * button, gpointer user_data)
{
	search_clear_results();

	gtk_widget_set_sensitive(button_search_clear, FALSE);
	gtk_widget_set_sensitive(popup_search_clear_results, FALSE);

}


void
on_popup_search_clear_results_activate(GtkMenuItem * menuitem,
									   gpointer user_data)
{
	search_clear_results();

	gtk_widget_set_sensitive(button_search_clear, FALSE);
	gtk_widget_set_sensitive(popup_search_clear_results, FALSE);

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
