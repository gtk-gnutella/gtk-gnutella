
#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include "gnutella.h"

#include <gdk/gdkkeysyms.h>
#include <gtk/gtk.h>

#include <regex.h>

#include "support.h"

#include "search.h"
#include "filter.h"
#include "matching.h"
#include "misc.h"

#include "dialog-filters.h"

struct filter_page {
	struct search *sch;			/* NULL for the global filters pages */
	GtkWidget *table;			/* Table containing the filter lines */
	gint n_lines;				/* Number of lines for this page */
	GList *page_lines;			/* The lines of this page */
};

struct filter_page_line {
	struct filter_page *page;	/* Page of this line */
	GtkWidget *c_box;			/* Box containing a filter box */
	GtkWidget *f_box;			/* The filter box */
	GtkWidget *remove_button;	/* Button to remove the line */
};

enum filter_size_type {
	FILTER_BETWEEN,
	FILTER_LESS,
	FILTER_GREATER
};

typedef struct filter *(*filter_factory)(GtkWidget *);

GtkWidget *dialog_filters = NULL;
GtkWidget *f_notebook = NULL;

struct filter_page *filters_current_page = NULL;
static struct filter_page *global_filter_page = NULL;

/* */

gboolean on_dialog_filters_delete_event(GtkWidget *, GdkEvent *, gpointer);
void on_button_apply_clicked(GtkButton *, gpointer);
void on_button_cancel_clicked(GtkButton *, gpointer);
void on_button_add_text_filter_clicked(GtkButton *, gpointer);
void on_button_add_ip_filter_clicked(GtkButton *, gpointer);
void on_button_add_size_filter_clicked(GtkButton *, gpointer);
void on_button_remove_filter_clicked(GtkButton *, gpointer);

static void filter_free(struct filter *f, gpointer data);

/* */

struct filter_page *dialog_filters_new_page(struct search *sch)
{
	struct filter_page *fp;
	GtkWidget *label;

	fp = (struct filter_page *) g_malloc0(sizeof(struct filter_page));

	fp->sch = sch;

	if (sch)
		label = gtk_label_new(sch->query);
	else
		label = gtk_label_new("Global filters");

	gtk_widget_show(label);

	fp->table = gtk_table_new(2, 2, FALSE);
	gtk_table_set_row_spacings(GTK_TABLE(fp->table), 4);
	gtk_table_set_col_spacing(GTK_TABLE(fp->table), 0, 8);
	gtk_container_set_border_width(GTK_CONTAINER(fp->table), 4);
	gtk_widget_show(fp->table);

	gtk_object_set_user_data((GtkObject *) fp->table, (gpointer) fp);

	gtk_notebook_append_page(GTK_NOTEBOOK(f_notebook), fp->table, label);

	return fp;
}

void on_filter_notebook_switch(GtkNotebook * notebook,
							   GtkNotebookPage * page, gint page_num,
							   gpointer user_data)
{
	struct filter_page *fp =
		gtk_object_get_user_data((GtkObject *) page->child);
	g_return_if_fail(fp);
	filters_current_page = fp;
}

GtkWidget *create_dialog_filters(void)
{
	GtkWidget *vbox_main;
	GtkWidget *hbox1;
	GtkWidget *button;
	GtkWidget *hbuttonbox1;
	GtkWidget *button_apply;
	GtkWidget *button_cancel;
	GtkWidget *sep;

	dialog_filters = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_object_set_data(GTK_OBJECT(dialog_filters), "dialog_filters",
						dialog_filters);
	gtk_window_set_title(GTK_WINDOW(dialog_filters),
						 "Search results filters");

	gtk_window_set_policy(GTK_WINDOW(dialog_filters), FALSE, FALSE, TRUE);

	vbox_main = gtk_vbox_new(FALSE, 0);
	gtk_widget_show(vbox_main);
	gtk_container_add(GTK_CONTAINER(dialog_filters), vbox_main);

	f_notebook = gtk_notebook_new();
	gtk_widget_ref(f_notebook);
	gtk_object_set_data_full(GTK_OBJECT(dialog_filters), "f_notebook",
							 f_notebook,
							 (GtkDestroyNotify) gtk_widget_unref);
	gtk_notebook_set_scrollable(GTK_NOTEBOOK(f_notebook), TRUE);
	gtk_widget_show(f_notebook);
	gtk_box_pack_start(GTK_BOX(vbox_main), f_notebook, TRUE, TRUE, 0);
	gtk_signal_connect(GTK_OBJECT(f_notebook), "switch-page",
					   GTK_SIGNAL_FUNC(on_filter_notebook_switch), NULL);

	global_filter_page = dialog_filters_new_page(NULL);

	hbox1 = gtk_hbox_new(FALSE, 10);
	gtk_widget_ref(hbox1);
	gtk_object_set_data_full(GTK_OBJECT(dialog_filters), "hbox1", hbox1,
							 (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show(hbox1);
	gtk_box_pack_start(GTK_BOX(vbox_main), hbox1, FALSE, FALSE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbox1), 5);

	button = gtk_button_new_with_label("Add text filter");
	gtk_widget_ref(button);
	gtk_object_set_data_full(GTK_OBJECT(dialog_filters), "button1", button,
							 (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show(button);
	gtk_box_pack_start(GTK_BOX(hbox1), button, FALSE, FALSE, 0);
	gtk_signal_connect(GTK_OBJECT(button), "clicked",
					   GTK_SIGNAL_FUNC(on_button_add_text_filter_clicked),
					   NULL);

	button = gtk_button_new_with_label("Add IP filter");
	gtk_widget_ref(button);
	gtk_object_set_data_full(GTK_OBJECT(dialog_filters), "button2", button,
							 (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show(button);
	gtk_box_pack_start(GTK_BOX(hbox1), button, FALSE, FALSE, 0);
	gtk_signal_connect(GTK_OBJECT(button), "clicked",
					   GTK_SIGNAL_FUNC(on_button_add_ip_filter_clicked),
					   NULL);

	button = gtk_button_new_with_label("Add size filter");
	gtk_widget_ref(button);
	gtk_object_set_data_full(GTK_OBJECT(dialog_filters), "button3", button,
							 (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show(button);
	gtk_box_pack_start(GTK_BOX(hbox1), button, FALSE, FALSE, 0);
	gtk_signal_connect(GTK_OBJECT(button), "clicked",
					   GTK_SIGNAL_FUNC(on_button_add_size_filter_clicked),
					   NULL);

	sep = gtk_hseparator_new();
	gtk_widget_show(sep);
	gtk_container_add(GTK_CONTAINER(vbox_main), sep);

	hbuttonbox1 = gtk_hbutton_box_new();
	gtk_widget_ref(hbuttonbox1);
	gtk_object_set_data_full(GTK_OBJECT(dialog_filters), "hbuttonbox1",
							 hbuttonbox1,
							 (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show(hbuttonbox1);
	gtk_box_pack_start(GTK_BOX(vbox_main), hbuttonbox1, FALSE, TRUE, 0);
	gtk_container_set_border_width(GTK_CONTAINER(hbuttonbox1), 6);
	gtk_button_box_set_layout(GTK_BUTTON_BOX(hbuttonbox1),
							  GTK_BUTTONBOX_SPREAD);

	button_apply = gtk_button_new_with_label("Apply filters");
	gtk_widget_ref(button_apply);
	gtk_object_set_data_full(GTK_OBJECT(dialog_filters), "button_apply",
							 button_apply,
							 (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show(button_apply);
	gtk_container_add(GTK_CONTAINER(hbuttonbox1), button_apply);
	GTK_WIDGET_SET_FLAGS(button_apply, GTK_CAN_DEFAULT);

	button_cancel = gtk_button_new_with_label("Cancel");
	gtk_widget_ref(button_cancel);
	gtk_object_set_data_full(GTK_OBJECT(dialog_filters), "button_cancel",
							 button_cancel,
							 (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show(button_cancel);
	gtk_container_add(GTK_CONTAINER(hbuttonbox1), button_cancel);
	GTK_WIDGET_SET_FLAGS(button_cancel, GTK_CAN_DEFAULT);

	gtk_signal_connect(GTK_OBJECT(dialog_filters), "delete_event",
					   GTK_SIGNAL_FUNC(on_dialog_filters_delete_event),
					   NULL);
	gtk_signal_connect(GTK_OBJECT(button_apply), "clicked",
					   GTK_SIGNAL_FUNC(on_button_apply_clicked), NULL);
	gtk_signal_connect(GTK_OBJECT(button_cancel), "clicked",
					   GTK_SIGNAL_FUNC(on_button_cancel_clicked), NULL);

	gtk_window_set_position(GTK_WINDOW(dialog_filters),
							GTK_WIN_POS_CENTER);

	return dialog_filters;
}

void filters_init(void)
{
	create_dialog_filters();
}


void filters_open_dialog(void)
{
	gtk_widget_show(dialog_filters);
	gdk_window_raise(dialog_filters->window);
}

void filters_new_search(struct search *sch)
{
	g_return_if_fail(sch);
	sch->filter_page = (gpointer) dialog_filters_new_page(sch);
}

static void free_filter_page(struct filter_page *fp)
{
	GList *l;

	for (l = g_list_first(fp->page_lines); l; l = g_list_next(l)) {
		struct filter_page_line *fpl = (struct filter_page_line *) l->data;

		gtk_widget_destroy(fpl->remove_button);
		gtk_widget_destroy(fpl->f_box);
		gtk_widget_destroy(fpl->c_box);

		g_free(fpl);
	}
	g_list_free(fp->page_lines);

	gtk_notebook_remove_page(GTK_NOTEBOOK(f_notebook),
		gtk_notebook_page_num(GTK_NOTEBOOK(f_notebook), fp->table));

	g_free(fp);
}

void filters_close_search(struct search *sch)
{
	g_return_if_fail(sch);

	free_filter_page((struct filter_page *) sch->filter_page);

	g_list_foreach(sch->filters, (GFunc)filter_free, NULL);
	g_list_free(sch->filters);
}

/*
 * filters_shutdown
 *
 * Free global filters.
 */
void filters_shutdown(void)
{
	free_filter_page(global_filter_page);

	g_list_foreach(global_filters, (GFunc)filter_free, NULL);
	g_list_free(global_filters);
}

/*
 * Callbacks
 */

/* Create a new filter box */

GtkWidget *new_filter_create_box(struct filter_page *fp)
{
	struct filter_page_line *fpl;

	if (!fp) {
		/* We'll use the current page */

		g_return_val_if_fail(filters_current_page, NULL);
		fp = filters_current_page;
	}

	/* Create the line */

	fpl =
		(struct filter_page_line *)
		g_malloc0(sizeof(struct filter_page_line));

	fpl->page = fp;

	fpl->c_box = gtk_hbox_new(FALSE, 0);
	gtk_widget_show(fpl->c_box);

	fpl->f_box = gtk_hbox_new(FALSE, 2);
	gtk_widget_show(fpl->f_box);
	gtk_box_pack_start(GTK_BOX(fpl->c_box), fpl->f_box, TRUE, TRUE, 0);

	fpl->remove_button = gtk_button_new_with_label("Remove");
	gtk_signal_connect(GTK_OBJECT(fpl->remove_button), "clicked",
					   GTK_SIGNAL_FUNC(on_button_remove_filter_clicked),
					   (gpointer) fpl);
	gtk_widget_show(fpl->remove_button);

	/* Insert the line into the page */

	fp->page_lines = g_list_append(fp->page_lines, (gpointer) fpl);

	gtk_table_resize(GTK_TABLE(fp->table), 2, fp->n_lines + 2);

	gtk_table_attach(GTK_TABLE(fp->table), fpl->c_box, 0, 1, fp->n_lines,
					 fp->n_lines + 1,
					 (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
					 (GtkAttachOptions) (GTK_EXPAND), 0, 0);
	gtk_table_attach(GTK_TABLE(fp->table), fpl->remove_button, 1, 2,
					 fp->n_lines, fp->n_lines + 1,
					 (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
					 (GtkAttachOptions) (GTK_EXPAND), 0, 0);

	gtk_table_set_row_spacings(GTK_TABLE(fp->table), 4);

	fp->n_lines++;

	/* Return the filter box */

	return fpl->f_box;
}

/* Remove a filter from a page */

void on_button_remove_filter_clicked(GtkButton * button,
									 gpointer user_data)
{
	struct filter_page *fp;
	struct filter_page_line *fpl, *fpl_next;
	GList *l;

	fpl = (struct filter_page_line *) user_data;
	g_return_if_fail(fpl);

	fp = fpl->page;

	l = g_list_find(fp->page_lines, (gpointer) fpl);
	g_return_if_fail(l);

	gtk_widget_destroy(fpl->f_box);		/* Destroy the filter box */

	while ((l = l->next)) {
		fpl_next = (struct filter_page_line *) l->data;

		/* Move the filter box to the previous line */

		fpl->f_box = fpl_next->f_box;

		gtk_widget_reparent(fpl_next->f_box, fpl->c_box);

		fpl = fpl_next;
	}

	/* Free the last line, then resize the table */

	gtk_widget_destroy(fpl->remove_button);
	gtk_widget_destroy(fpl->c_box);

	fp->page_lines = g_list_remove(fp->page_lines, (gpointer) fpl);

	g_free(fpl);

	gtk_table_resize(GTK_TABLE(fp->table), 2, --(fp->n_lines) + 2);
}

/*
 * Adding filters :
 *
 * if the search parameter is null, we add the filter to the currently
 * displayed page of the filters notebook
 */

/* create a text filter structure from the widgets in BOX
 * has to conform closely to the interface created in the next function
 */
static struct filter *make_text_filter(GtkWidget *box)
{
	GList *children;
	struct filter *f;

	f = g_new(struct filter, 1);
	f->type = FILTER_TEXT;
	children = gtk_container_children(GTK_CONTAINER(box));
	f->u.text.type = (enum filter_text_type)gtk_object_get_user_data((GtkObject *)gtk_menu_get_active(GTK_MENU(gtk_option_menu_get_menu(GTK_OPTION_MENU(GTK_WIDGET(g_list_nth_data(children, 1)))))));
	f->u.text.u.match = gtk_editable_get_chars(GTK_EDITABLE(g_list_nth_data(children, 2)), 0, -1);
	f->u.text.case_sensitive = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(g_list_nth_data(children, 3)));
	f->positive = (int)gtk_object_get_user_data((GtkObject *)gtk_menu_get_active(GTK_MENU(gtk_option_menu_get_menu(GTK_OPTION_MENU(GTK_WIDGET(g_list_nth_data(children, 5)))))));
	if (!f->u.text.case_sensitive)
		strlower(f->u.text.u.match, f->u.text.u.match);
	if (f->u.text.type == FILTER_WORDS) {
		char *s;
		GList *l = NULL;
		for (s = strtok(f->u.text.u.match, " \t\n"); s;
		     s = strtok(NULL,		   " \t\n"))
			l = g_list_append(l, pattern_compile(s));
		g_free(f->u.text.u.match);
		f->u.text.u.words = l;
	} else if (f->u.text.type == FILTER_REGEXP) {
		int err;
		regex_t *re;
		re = g_new(regex_t, 1);
		err = regcomp(re, f->u.text.u.match,
			      REG_NOSUB|(f->u.text.case_sensitive ? 0
								  : REG_ICASE));
		if (err) {
			char buf[1000];
			regerror(err, re, buf, 1000);
			g_warning("problem in regular expression: %s"
				  "; falling back to substring match", buf);
			f->u.text.type = FILTER_SUBSTR;
		} else {
			g_free(f->u.text.u.match);
			f->u.text.u.re = re;
		}
	}
	/* no "else" because REGEXP can fall back here */
	if (f->u.text.type == FILTER_SUBSTR)
		f->u.text.u.pattern = pattern_compile(f->u.text.u.match);
	return f;
}

/* Add a text filter */

void on_button_add_text_filter_clicked(GtkButton * button, gpointer search)
{
	GtkWidget *box;
	GtkWidget *label;
	GtkWidget *optionmenu1;
	GtkWidget *optionmenu1_menu;
	GtkWidget *glade_menuitem;
	GtkWidget *entry1;
	GtkWidget *checkbutton1;
	GtkWidget *optionmenu2;
	GtkWidget *optionmenu2_menu;

	box = new_filter_create_box(NULL);
	gtk_object_set_user_data((GtkObject *)box, (gpointer)make_text_filter);

	label = gtk_label_new("If filename");
	gtk_widget_show(label);
	gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 0);

	optionmenu1 = gtk_option_menu_new();
	gtk_widget_show(optionmenu1);
	gtk_box_pack_start(GTK_BOX(box), optionmenu1, FALSE, FALSE, 0);
	optionmenu1_menu = gtk_menu_new();
	glade_menuitem = gtk_menu_item_new_with_label("starts with");
	gtk_object_set_user_data((GtkObject *)glade_menuitem,
				 (gpointer)FILTER_PREFIX);
	gtk_widget_show(glade_menuitem);
	gtk_menu_append(GTK_MENU(optionmenu1_menu), glade_menuitem);
	glade_menuitem = gtk_menu_item_new_with_label("contains the words");
	gtk_object_set_user_data((GtkObject *)glade_menuitem,
				 (gpointer)FILTER_WORDS);
	gtk_widget_show(glade_menuitem);
	gtk_menu_append(GTK_MENU(optionmenu1_menu), glade_menuitem);
	glade_menuitem = gtk_menu_item_new_with_label("ends with");
	gtk_object_set_user_data((GtkObject *)glade_menuitem,
				 (gpointer)FILTER_SUFFIX);
	gtk_widget_show(glade_menuitem);
	gtk_menu_append(GTK_MENU(optionmenu1_menu), glade_menuitem);
	glade_menuitem = gtk_menu_item_new_with_label("includes");
	gtk_object_set_user_data((GtkObject *)glade_menuitem,
				 (gpointer)FILTER_SUBSTR);
	gtk_widget_show(glade_menuitem);
	gtk_menu_append(GTK_MENU(optionmenu1_menu), glade_menuitem);
	glade_menuitem = gtk_menu_item_new_with_label("matches regex");
	gtk_object_set_user_data((GtkObject *)glade_menuitem,
				 (gpointer)FILTER_REGEXP);
	gtk_widget_show(glade_menuitem);
	gtk_menu_append(GTK_MENU(optionmenu1_menu), glade_menuitem);
	gtk_option_menu_set_menu(GTK_OPTION_MENU(optionmenu1),
							 optionmenu1_menu);

	entry1 = gtk_entry_new();
	gtk_widget_show(entry1);
	gtk_box_pack_start(GTK_BOX(box), entry1, TRUE, TRUE, 0);

	checkbutton1 = gtk_check_button_new_with_label("Case sensitive");
	gtk_widget_show(checkbutton1);
	gtk_box_pack_start(GTK_BOX(box), checkbutton1, FALSE, FALSE, 0);

	label = gtk_label_new("then");
	gtk_widget_show(label);
	gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 0);

	optionmenu2 = gtk_option_menu_new();
	gtk_widget_show(optionmenu2);
	gtk_box_pack_start(GTK_BOX(box), optionmenu2, FALSE, FALSE, 0);
	optionmenu2_menu = gtk_menu_new();
	glade_menuitem = gtk_menu_item_new_with_label("display");
	gtk_object_set_user_data((GtkObject *)glade_menuitem,
				 (gpointer)1);
	gtk_widget_show(glade_menuitem);
	gtk_menu_append(GTK_MENU(optionmenu2_menu), glade_menuitem);
	glade_menuitem = gtk_menu_item_new_with_label("don't display");
	gtk_object_set_user_data((GtkObject *)glade_menuitem,
				 (gpointer)0);
	gtk_widget_show(glade_menuitem);
	gtk_menu_append(GTK_MENU(optionmenu2_menu), glade_menuitem);
	gtk_option_menu_set_menu(GTK_OPTION_MENU(optionmenu2),
							 optionmenu2_menu);
}

/* create an ip filter structure from the widgets in BOX
 * has to conform closely to the interface created in the next function
 */
static struct filter *make_ip_filter(GtkWidget *box)
{
	GList *children;
	struct filter *f;
	char *s;

	f = g_new(struct filter, 1);
	f->type = FILTER_IP;
	children = gtk_container_children(GTK_CONTAINER(box));
	s = gtk_editable_get_chars(GTK_EDITABLE(g_list_nth_data(children, 1)), 0, -1);
	f->u.ip.addr = ntohl(inet_addr(s));
	g_free(s);
	s = gtk_editable_get_chars(GTK_EDITABLE(g_list_nth_data(children, 3)), 0, -1);
	f->u.ip.mask = ntohl(inet_addr(s));
	g_free(s);
	f->u.ip.addr &= f->u.ip.mask;
	f->positive = (int)gtk_object_get_user_data((GtkObject *)gtk_menu_get_active(GTK_MENU(gtk_option_menu_get_menu(GTK_OPTION_MENU(GTK_WIDGET(g_list_nth_data(children, 5)))))));
	return f;
}

/* Add an IP filter */

void on_button_add_ip_filter_clicked(GtkButton * button, gpointer search)
{
	GtkWidget *box;
	GtkWidget *label3;
	GtkWidget *entry2;
	GtkWidget *label4;
	GtkWidget *entry3;
	GtkWidget *label5;
	GtkWidget *optionmenu3;
	GtkWidget *optionmenu3_menu;
	GtkWidget *glade_menuitem;

	box = new_filter_create_box(NULL);
	gtk_object_set_user_data((GtkObject *)box, (gpointer)make_ip_filter);

	label3 = gtk_label_new("If IP address matches");
	gtk_widget_show(label3);
	gtk_box_pack_start(GTK_BOX(box), label3, FALSE, FALSE, 0);

	entry2 = gtk_entry_new();
	gtk_widget_show(entry2);
	gtk_box_pack_start(GTK_BOX(box), entry2, TRUE, TRUE, 0);

	label4 = gtk_label_new("mask");
	gtk_widget_show(label4);
	gtk_box_pack_start(GTK_BOX(box), label4, FALSE, FALSE, 0);

	entry3 = gtk_entry_new();
	gtk_widget_show(entry3);
	gtk_box_pack_start(GTK_BOX(box), entry3, TRUE, TRUE, 0);

	label5 = gtk_label_new("then");
	gtk_widget_show(label5);
	gtk_box_pack_start(GTK_BOX(box), label5, FALSE, FALSE, 0);

	optionmenu3 = gtk_option_menu_new();
	gtk_widget_show(optionmenu3);
	gtk_box_pack_start(GTK_BOX(box), optionmenu3, FALSE, FALSE, 0);
	optionmenu3_menu = gtk_menu_new();
	glade_menuitem = gtk_menu_item_new_with_label("display");
	gtk_object_set_user_data((GtkObject *)glade_menuitem,
				 (gpointer)1);
	gtk_widget_show(glade_menuitem);
	gtk_menu_append(GTK_MENU(optionmenu3_menu), glade_menuitem);
	glade_menuitem = gtk_menu_item_new_with_label("don't display");
	gtk_object_set_user_data((GtkObject *)glade_menuitem,
				 (gpointer)0);
	gtk_widget_show(glade_menuitem);
	gtk_menu_append(GTK_MENU(optionmenu3_menu), glade_menuitem);
	gtk_option_menu_set_menu(GTK_OPTION_MENU(optionmenu3),
							 optionmenu3_menu);
	gtk_option_menu_set_history(GTK_OPTION_MENU(optionmenu3), 1);
}

/* create a size filter structure from the widgets in BOX
 * has to conform closely to the interface created in the next function
 */
static struct filter *make_size_filter(GtkWidget *box)
{
	GList *children;
	struct filter *f;
	char *s, *err;
	enum filter_size_type t;
	size_t n;

	f = g_new(struct filter, 1);
	f->type = FILTER_SIZE;
	children = gtk_container_children(GTK_CONTAINER(box));
	t = (enum filter_size_type)gtk_object_get_user_data((GtkObject *)gtk_menu_get_active(GTK_MENU(gtk_option_menu_get_menu(GTK_OPTION_MENU(GTK_WIDGET(g_list_nth_data(children, 1)))))));
	s = gtk_editable_get_chars(GTK_EDITABLE(g_list_nth_data(children, 2)), 0, -1);
	n = strtoul(s, &err, 10);
	if (*err)
		g_warning("ignoring non-numeric '%s'", err);
	g_free(s);
	if (t == FILTER_LESS) {
		f->u.size.lower = 0;
		f->u.size.upper = n;
	} else {
		f->u.size.lower = n;
		if (t == FILTER_GREATER)
			f->u.size.upper = ~0L;
		else {
			g_assert(t == FILTER_BETWEEN);
			s = gtk_editable_get_chars(GTK_EDITABLE(g_list_nth_data(children, 4)), 0, -1);
			f->u.size.upper = strtoul(s, &err, 10);
			if (*err)
				g_warning("ignoring non-numeric '%s'", err);
			if (f->u.size.upper < n) { /* == f->u.size.upper */
				f->u.size.lower = f->u.size.upper;
				f->u.size.upper = n;
			}
			g_free(s);
		}
	}
	f->positive = (int)gtk_object_get_user_data((GtkObject *)gtk_menu_get_active(GTK_MENU(gtk_option_menu_get_menu(GTK_OPTION_MENU(GTK_WIDGET(g_list_nth_data(children, 6)))))));	
	return f;
}

/* Add a size filter */

void on_button_add_size_filter_clicked(GtkButton * button, gpointer search)
{
	GtkWidget *box;
	GtkWidget *label;
	GtkWidget *entry4;
	GtkWidget *entry5;
	GtkWidget *optionmenu4;
	GtkWidget *optionmenu4_menu;
	GtkWidget *glade_menuitem;
	GtkWidget *optionmenu5;
	GtkWidget *optionmenu5_menu;

	box = new_filter_create_box(NULL);
	gtk_object_set_user_data((GtkObject *)box, (gpointer)make_size_filter);

	label = gtk_label_new("If file size");
	gtk_widget_show(label);
	gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 0);

	optionmenu4 = gtk_option_menu_new();
	gtk_widget_show(optionmenu4);
	gtk_box_pack_start(GTK_BOX(box), optionmenu4, FALSE, FALSE, 0);
	optionmenu4_menu = gtk_menu_new();
	glade_menuitem = gtk_menu_item_new_with_label("is between");
	gtk_object_set_user_data((GtkObject *)glade_menuitem,
				 (gpointer)FILTER_BETWEEN);
	gtk_widget_show(glade_menuitem);
	gtk_menu_append(GTK_MENU(optionmenu4_menu), glade_menuitem);
	glade_menuitem = gtk_menu_item_new_with_label("is greater than");
	gtk_object_set_user_data((GtkObject *)glade_menuitem,
				 (gpointer)FILTER_GREATER);
	gtk_widget_show(glade_menuitem);
	gtk_menu_append(GTK_MENU(optionmenu4_menu), glade_menuitem);
	glade_menuitem = gtk_menu_item_new_with_label("is less than");
	gtk_object_set_user_data((GtkObject *)glade_menuitem,
				 (gpointer)FILTER_LESS);
	gtk_widget_show(glade_menuitem);
	gtk_menu_append(GTK_MENU(optionmenu4_menu), glade_menuitem);
	gtk_option_menu_set_menu(GTK_OPTION_MENU(optionmenu4),
							 optionmenu4_menu);

	entry4 = gtk_entry_new();
	gtk_widget_show(entry4);
	gtk_box_pack_start(GTK_BOX(box), entry4, TRUE, TRUE, 0);

	label = gtk_label_new("and");
	gtk_widget_show(label);
	gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 0);

	entry5 = gtk_entry_new();
	gtk_widget_show(entry5);
	gtk_box_pack_start(GTK_BOX(box), entry5, TRUE, TRUE, 0);

	label = gtk_label_new("then");
	gtk_widget_show(label);
	gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 0);

	optionmenu5 = gtk_option_menu_new();
	gtk_widget_show(optionmenu5);
	gtk_box_pack_start(GTK_BOX(box), optionmenu5, FALSE, FALSE, 0);
	optionmenu5_menu = gtk_menu_new();
	glade_menuitem = gtk_menu_item_new_with_label("display");
	gtk_object_set_user_data((GtkObject *)glade_menuitem,
				 (gpointer)1);
	gtk_widget_show(glade_menuitem);
	gtk_menu_append(GTK_MENU(optionmenu5_menu), glade_menuitem);
	glade_menuitem = gtk_menu_item_new_with_label("don't display");
	gtk_object_set_user_data((GtkObject *)glade_menuitem,
				 (gpointer)0);
	gtk_widget_show(glade_menuitem);
	gtk_menu_append(GTK_MENU(optionmenu5_menu), glade_menuitem);
	gtk_option_menu_set_menu(GTK_OPTION_MENU(optionmenu5),
							 optionmenu5_menu);
	gtk_option_menu_set_history(GTK_OPTION_MENU(optionmenu5), 1);
}

gboolean on_dialog_filters_delete_event(GtkWidget * widget,
										GdkEvent * event,
										gpointer user_data)
{
	gtk_widget_hide(dialog_filters);
	return TRUE;
}

static void make_filter(gpointer filter, GList **data)
{
	filter_factory factory;
	GtkWidget *f_box;
	struct filter *f;

	f_box = ((struct filter_page_line *)filter)->f_box;
	g_assert(f_box);
	factory = (filter_factory)gtk_object_get_user_data((GtkObject *)f_box); 
	g_assert(factory);
	f = factory(f_box);
	if (f)
		*data = g_list_append(*data, (gpointer)f);
}

static void filter_free(struct filter *f, gpointer data)
{
	if (f->type == FILTER_TEXT)
		switch (f->u.text.type) {
		case FILTER_WORDS:
			g_list_foreach(f->u.text.u.words, (GFunc)pattern_free,
				       NULL);
			g_list_free(f->u.text.u.words);
			break;
		case FILTER_SUBSTR:
			pattern_free(f->u.text.u.pattern);
			break;
		case FILTER_REGEXP:
			regfree(f->u.text.u.re);
			break;
		case FILTER_PREFIX:
		case FILTER_SUFFIX:
			g_free(f->u.text.u.match);
			break;
		default:
			g_error("don't know how to free text filter type %d",
				f->u.text.type);
		}
	g_free(f);
}

static void page_apply(GtkWidget *page, gpointer data)
{
	struct filter_page *fp;
	GList **list;

	fp = (struct filter_page *)gtk_object_get_user_data((GtkObject *)page);
	g_assert(fp);
	list = fp->sch ? &fp->sch->filters : &global_filters;
	g_list_foreach(*list, (GFunc)filter_free, NULL);
	g_list_free(*list);
	*list = NULL;
	g_list_foreach(fp->page_lines, (GFunc)make_filter, list);
}

void on_button_apply_clicked(GtkButton * button, gpointer user_data)
{
	gtk_container_foreach(GTK_CONTAINER(f_notebook), page_apply, NULL);
	gtk_widget_hide(dialog_filters);
}

void on_button_cancel_clicked(GtkButton * button, gpointer user_data)
{
	gtk_widget_hide(dialog_filters);
}

/*
 * Callbacks for the main window
 */

void on_button_search_filter_clicked(GtkButton * button,
									 gpointer user_data)
{
	filters_open_dialog();
}

/* vi: set ts=4: */
