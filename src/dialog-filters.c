
#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include "gnutella.h"

#include <gdk/gdkkeysyms.h>
#include <gtk/gtk.h>

#include "dialog-filters.h"
#include "support.h"

#include "search.h"
#include "filter.h"

GtkWidget *dialog_filters = NULL;

gboolean on_dialog_filters_delete_event(GtkWidget *widget, GdkEvent *event, gpointer user_data);
void on_button_apply_clicked (GtkButton *button, gpointer user_data);
void on_button_cancel_clicked (GtkButton *button, gpointer user_data);
void on_button_add_text_filter_clicked (GtkButton *button, gpointer user_data);
void on_button_add_ip_filter_clicked (GtkButton *button, gpointer user_data);
void on_button_add_size_filter_clicked (GtkButton *button, gpointer user_data);

GtkWidget *f_notebook = NULL;
GtkWidget *f_global_table = NULL;

GtkWidget* create_dialog_filters (void)
{
	GtkWidget *vbox_main;
	GtkWidget *vseparator1;
	GtkWidget *hbox1;
	GtkWidget *button;
	GtkWidget *label_global;
	GtkWidget *hbuttonbox1;
	GtkWidget *button_apply;
	GtkWidget *button_cancel;

	dialog_filters = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	gtk_object_set_data (GTK_OBJECT (dialog_filters), "dialog_filters", dialog_filters);
	gtk_window_set_title (GTK_WINDOW (dialog_filters), "Search results filters");

	vbox_main = gtk_vbox_new (FALSE, 0);
	gtk_widget_ref (vbox_main);
	gtk_object_set_data_full (GTK_OBJECT (dialog_filters), "vbox_main", vbox_main, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (vbox_main);
	gtk_container_add (GTK_CONTAINER (dialog_filters), vbox_main);

	f_notebook = gtk_notebook_new ();
	gtk_widget_ref (f_notebook);
	gtk_object_set_data_full (GTK_OBJECT (dialog_filters), "f_notebook", f_notebook, (GtkDestroyNotify) gtk_widget_unref);
	gtk_notebook_set_scrollable(GTK_NOTEBOOK(f_notebook), TRUE);
	gtk_widget_show (f_notebook);
	gtk_box_pack_start (GTK_BOX (vbox_main), f_notebook, TRUE, TRUE, 0);

	f_global_table = gtk_table_new (2, 3, FALSE);
	gtk_widget_ref (f_global_table);
	gtk_object_set_data_full (GTK_OBJECT (dialog_filters), "f_global_table", f_global_table, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (f_global_table);
	gtk_container_add (GTK_CONTAINER (f_notebook), f_global_table);
	
	vseparator1 = gtk_vseparator_new ();
	gtk_widget_ref (vseparator1);
	gtk_object_set_data_full (GTK_OBJECT (dialog_filters), "vseparator1", vseparator1, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (vseparator1);
	gtk_table_attach (GTK_TABLE (f_global_table), vseparator1, 1, 2, 0, 2, (GtkAttachOptions) (GTK_EXPAND | GTK_FILL), (GtkAttachOptions) (GTK_EXPAND | GTK_FILL), 0, 0);

	hbox1 = gtk_hbox_new (FALSE, 10);
	gtk_widget_ref (hbox1);
	gtk_object_set_data_full (GTK_OBJECT (dialog_filters), "hbox1", hbox1, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (hbox1);
	gtk_box_pack_start (GTK_BOX (vbox_main), hbox1, TRUE, TRUE, 0);
	gtk_container_set_border_width (GTK_CONTAINER (hbox1), 5);

	button = gtk_button_new_with_label ("Add text filter");
	gtk_widget_ref (button);
	gtk_object_set_data_full (GTK_OBJECT (dialog_filters), "button1", button, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (button);
	gtk_box_pack_start (GTK_BOX (hbox1), button, FALSE, FALSE, 0);
	gtk_signal_connect(GTK_OBJECT(button), "clicked", GTK_SIGNAL_FUNC(on_button_add_text_filter_clicked), NULL);
 
	button = gtk_button_new_with_label ("Add IP filter");
	gtk_widget_ref (button);
	gtk_object_set_data_full (GTK_OBJECT (dialog_filters), "button2", button, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (button);
	gtk_box_pack_start (GTK_BOX (hbox1), button, FALSE, FALSE, 0);
	gtk_signal_connect(GTK_OBJECT(button), "clicked", GTK_SIGNAL_FUNC(on_button_add_ip_filter_clicked), NULL);

	button = gtk_button_new_with_label ("Add size filter");
	gtk_widget_ref (button);
	gtk_object_set_data_full (GTK_OBJECT (dialog_filters), "button3", button, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (button);
	gtk_box_pack_start (GTK_BOX (hbox1), button, FALSE, FALSE, 0);
	gtk_signal_connect(GTK_OBJECT(button), "clicked", GTK_SIGNAL_FUNC(on_button_add_size_filter_clicked), NULL);

	label_global = gtk_label_new ("Global filters");
	gtk_widget_ref (label_global);
	gtk_object_set_data_full (GTK_OBJECT (dialog_filters), "label_global", label_global, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (label_global);
	gtk_notebook_set_tab_label (GTK_NOTEBOOK (f_notebook), gtk_notebook_get_nth_page (GTK_NOTEBOOK (f_notebook), 0), label_global);

	hbuttonbox1 = gtk_hbutton_box_new ();
	gtk_widget_ref (hbuttonbox1);
	gtk_object_set_data_full (GTK_OBJECT (dialog_filters), "hbuttonbox1", hbuttonbox1, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (hbuttonbox1);
	gtk_box_pack_start (GTK_BOX (vbox_main), hbuttonbox1, FALSE, TRUE, 0);
	gtk_container_set_border_width (GTK_CONTAINER (hbuttonbox1), 6);
	gtk_button_box_set_layout (GTK_BUTTON_BOX (hbuttonbox1), GTK_BUTTONBOX_SPREAD);

	button_apply = gtk_button_new_with_label ("Apply filters");
	gtk_widget_ref (button_apply);
	gtk_object_set_data_full (GTK_OBJECT (dialog_filters), "button_apply", button_apply, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (button_apply);
	gtk_container_add (GTK_CONTAINER (hbuttonbox1), button_apply);
	GTK_WIDGET_SET_FLAGS (button_apply, GTK_CAN_DEFAULT);

	button_cancel = gtk_button_new_with_label ("Cancel");
	gtk_widget_ref (button_cancel);
	gtk_object_set_data_full (GTK_OBJECT (dialog_filters), "button_cancel", button_cancel, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (button_cancel);
	gtk_container_add (GTK_CONTAINER (hbuttonbox1), button_cancel);
	GTK_WIDGET_SET_FLAGS (button_cancel, GTK_CAN_DEFAULT);

	gtk_signal_connect (GTK_OBJECT (dialog_filters), "delete_event", GTK_SIGNAL_FUNC (on_dialog_filters_delete_event), NULL);
	gtk_signal_connect (GTK_OBJECT (button_apply), "clicked", GTK_SIGNAL_FUNC (on_button_apply_clicked), NULL);
	gtk_signal_connect (GTK_OBJECT (button_cancel), "clicked", GTK_SIGNAL_FUNC (on_button_cancel_clicked), NULL);

	gtk_window_set_position(GTK_WINDOW(dialog_filters), GTK_WIN_POS_CENTER);

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

/* Callbacks -------------------------------------------------------------------------------------------------- */

// Adding filters :
//
// Adds the filter to the current notebook page
//
// There is one page per active search + the global filter page
//
//

/* Add a text filter */

void on_button_add_text_filter_clicked (GtkButton *button, gpointer user_data)
{
	GtkWidget *hbox1;
	GtkWidget *label1;
	GtkWidget *optionmenu1;
	GtkWidget *optionmenu1_menu;
	GtkWidget *glade_menuitem;
	GtkWidget *entry1;
	GtkWidget *checkbutton1;
	GtkWidget *label2;
	GtkWidget *optionmenu2;
	GtkWidget *optionmenu2_menu;

	return;

	hbox1 = gtk_hbox_new (FALSE, 2);
	gtk_widget_ref (hbox1);
	gtk_object_set_data_full (GTK_OBJECT (main_window), "hbox1", hbox1, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (hbox1);

	/* Put hbox1 in the notebook here */
	gtk_table_attach (GTK_TABLE (f_global_table), hbox1, 0, 1, 0, 2, (GtkAttachOptions) (GTK_EXPAND | GTK_FILL), (GtkAttachOptions) (GTK_EXPAND | GTK_FILL), 0, 0);


	label1 = gtk_label_new ("If filename");
	gtk_widget_ref (label1);
	gtk_object_set_data_full (GTK_OBJECT (main_window), "label1", label1, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (label1);
	gtk_box_pack_start (GTK_BOX (hbox1), label1, FALSE, FALSE, 0);

	optionmenu1 = gtk_option_menu_new ();
	gtk_widget_ref (optionmenu1);
	gtk_object_set_data_full (GTK_OBJECT (main_window), "optionmenu1", optionmenu1, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (optionmenu1);
	gtk_box_pack_start (GTK_BOX (hbox1), optionmenu1, FALSE, FALSE, 0);
	optionmenu1_menu = gtk_menu_new ();
	glade_menuitem = gtk_menu_item_new_with_label ("starts with");
	gtk_widget_show (glade_menuitem);
	gtk_menu_append (GTK_MENU (optionmenu1_menu), glade_menuitem);
	glade_menuitem = gtk_menu_item_new_with_label ("contains the words");
	gtk_widget_show (glade_menuitem);
	gtk_menu_append (GTK_MENU (optionmenu1_menu), glade_menuitem);
	glade_menuitem = gtk_menu_item_new_with_label ("ends with");
	gtk_widget_show (glade_menuitem);
	gtk_menu_append (GTK_MENU (optionmenu1_menu), glade_menuitem);
	glade_menuitem = gtk_menu_item_new_with_label ("includes");
	gtk_widget_show (glade_menuitem);
	gtk_menu_append (GTK_MENU (optionmenu1_menu), glade_menuitem);
	glade_menuitem = gtk_menu_item_new_with_label ("matches regex");
	gtk_widget_show (glade_menuitem);
	gtk_menu_append (GTK_MENU (optionmenu1_menu), glade_menuitem);
	gtk_option_menu_set_menu (GTK_OPTION_MENU (optionmenu1), optionmenu1_menu);

	entry1 = gtk_entry_new ();
	gtk_widget_ref (entry1);
	gtk_object_set_data_full (GTK_OBJECT (main_window), "entry1", entry1, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (entry1);
	gtk_box_pack_start (GTK_BOX (hbox1), entry1, TRUE, TRUE, 0);

	checkbutton1 = gtk_check_button_new_with_label ("Case sensitive");
	gtk_widget_ref (checkbutton1);
	gtk_object_set_data_full (GTK_OBJECT (main_window), "checkbutton1", checkbutton1, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (checkbutton1);
	gtk_box_pack_start (GTK_BOX (hbox1), checkbutton1, FALSE, FALSE, 0);

	label2 = gtk_label_new ("then");
	gtk_widget_ref (label2);
	gtk_object_set_data_full (GTK_OBJECT (main_window), "label2", label2, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (label2);
	gtk_box_pack_start (GTK_BOX (hbox1), label2, FALSE, FALSE, 0);

	optionmenu2 = gtk_option_menu_new ();
	gtk_widget_ref (optionmenu2);
	gtk_object_set_data_full (GTK_OBJECT (main_window), "optionmenu2", optionmenu2, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (optionmenu2);
	gtk_box_pack_start (GTK_BOX (hbox1), optionmenu2, FALSE, FALSE, 0);
	optionmenu2_menu = gtk_menu_new ();
	glade_menuitem = gtk_menu_item_new_with_label ("display");
	gtk_widget_show (glade_menuitem);
	gtk_menu_append (GTK_MENU (optionmenu2_menu), glade_menuitem);
	glade_menuitem = gtk_menu_item_new_with_label ("don't display");
	gtk_widget_show (glade_menuitem);
	gtk_menu_append (GTK_MENU (optionmenu2_menu), glade_menuitem);
	gtk_option_menu_set_menu (GTK_OPTION_MENU (optionmenu2), optionmenu2_menu);
}

/* Add an IP filter */

void on_button_add_ip_filter_clicked (GtkButton *button, gpointer user_data)
{
	GtkWidget *hbox2;
	GtkWidget *label3;
	GtkWidget *entry2;
	GtkWidget *label4;
	GtkWidget *entry3;
	GtkWidget *label5;
	GtkWidget *optionmenu3;
	GtkWidget *optionmenu3_menu;
	GtkWidget *glade_menuitem;

	return;

	hbox2 = gtk_hbox_new (FALSE, 2);
	gtk_widget_ref (hbox2);
	gtk_object_set_data_full (GTK_OBJECT (main_window), "hbox2", hbox2, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (hbox2);

	/* Put hbox2 in the notebook here */
	gtk_table_attach (GTK_TABLE (f_global_table), hbox2, 0, 1, 0, 2, (GtkAttachOptions) (GTK_EXPAND | GTK_FILL), (GtkAttachOptions) (GTK_EXPAND | GTK_FILL), 0, 0);

	label3 = gtk_label_new ("If IP address matches");
	gtk_widget_ref (label3);
	gtk_object_set_data_full (GTK_OBJECT (main_window), "label3", label3, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (label3);
	gtk_box_pack_start (GTK_BOX (hbox2), label3, FALSE, FALSE, 0);

	entry2 = gtk_entry_new ();
	gtk_widget_ref (entry2);
	gtk_object_set_data_full (GTK_OBJECT (main_window), "entry2", entry2, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (entry2);
	gtk_box_pack_start (GTK_BOX (hbox2), entry2, TRUE, TRUE, 0);

	label4 = gtk_label_new ("mask");
	gtk_widget_ref (label4);
	gtk_object_set_data_full (GTK_OBJECT (main_window), "label4", label4, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (label4);
	gtk_box_pack_start (GTK_BOX (hbox2), label4, FALSE, FALSE, 0);

	entry3 = gtk_entry_new ();
	gtk_widget_ref (entry3);
	gtk_object_set_data_full (GTK_OBJECT (main_window), "entry3", entry3, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (entry3);
	gtk_box_pack_start (GTK_BOX (hbox2), entry3, TRUE, TRUE, 0);

	label5 = gtk_label_new ("then");
	gtk_widget_ref (label5);
	gtk_object_set_data_full (GTK_OBJECT (main_window), "label5", label5, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (label5);
	gtk_box_pack_start (GTK_BOX (hbox2), label5, FALSE, FALSE, 0);

	optionmenu3 = gtk_option_menu_new ();
	gtk_widget_ref (optionmenu3);
	gtk_object_set_data_full (GTK_OBJECT (main_window), "optionmenu3", optionmenu3, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (optionmenu3);
	gtk_box_pack_start (GTK_BOX (hbox2), optionmenu3, FALSE, FALSE, 0);
	optionmenu3_menu = gtk_menu_new ();
	glade_menuitem = gtk_menu_item_new_with_label ("display");
	gtk_widget_show (glade_menuitem);
	gtk_menu_append (GTK_MENU (optionmenu3_menu), glade_menuitem);
	glade_menuitem = gtk_menu_item_new_with_label ("don't display");
	gtk_widget_show (glade_menuitem);
	gtk_menu_append (GTK_MENU (optionmenu3_menu), glade_menuitem);
	gtk_option_menu_set_menu (GTK_OPTION_MENU (optionmenu3), optionmenu3_menu);
	gtk_option_menu_set_history (GTK_OPTION_MENU (optionmenu3), 1);
}

/* Add a size filter */

void on_button_add_size_filter_clicked (GtkButton *button, gpointer user_data)
{
	GtkWidget *hbox3;
	GtkWidget *label6;
	GtkWidget *entry4;
	GtkWidget *label7;
	GtkWidget *entry5;
	GtkWidget *label8;
	GtkWidget *optionmenu4;
	GtkWidget *optionmenu4_menu;
	GtkWidget *glade_menuitem;
	GtkWidget *optionmenu5;
	GtkWidget *optionmenu5_menu;

	return;

	hbox3 = gtk_hbox_new (FALSE, 4);
	gtk_widget_ref (hbox3);
	gtk_object_set_data_full (GTK_OBJECT (main_window), "hbox3", hbox3, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (hbox3);

	/* Put hbox3 in the notbook here */
	gtk_table_attach (GTK_TABLE (f_global_table), hbox3, 0, 1, 0, 2, (GtkAttachOptions) (GTK_EXPAND | GTK_FILL), (GtkAttachOptions) (GTK_EXPAND | GTK_FILL), 0, 0);

	label6 = gtk_label_new ("If file size");
	gtk_widget_ref (label6);
	gtk_object_set_data_full (GTK_OBJECT (main_window), "label6", label6, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (label6);
	gtk_box_pack_start (GTK_BOX (hbox3), label6, FALSE, FALSE, 0);

	optionmenu4 = gtk_option_menu_new ();
	gtk_widget_ref (optionmenu4);
	gtk_object_set_data_full (GTK_OBJECT (main_window), "optionmenu4", optionmenu4, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (optionmenu4);
	gtk_box_pack_start (GTK_BOX (hbox3), optionmenu4, FALSE, FALSE, 0);
	optionmenu4_menu = gtk_menu_new ();
	glade_menuitem = gtk_menu_item_new_with_label ("is between");
	gtk_widget_show (glade_menuitem);
	gtk_menu_append (GTK_MENU (optionmenu4_menu), glade_menuitem);
	glade_menuitem = gtk_menu_item_new_with_label ("is greater than");
	gtk_widget_show (glade_menuitem);
	gtk_menu_append (GTK_MENU (optionmenu4_menu), glade_menuitem);
	glade_menuitem = gtk_menu_item_new_with_label ("is less than");
	gtk_widget_show (glade_menuitem);
	gtk_menu_append (GTK_MENU (optionmenu4_menu), glade_menuitem);
	gtk_option_menu_set_menu (GTK_OPTION_MENU (optionmenu4), optionmenu4_menu);

	entry4 = gtk_entry_new ();
	gtk_widget_ref (entry4);
	gtk_object_set_data_full (GTK_OBJECT (main_window), "entry4", entry4, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (entry4);
	gtk_box_pack_start (GTK_BOX (hbox3), entry4, TRUE, TRUE, 0);

	label7 = gtk_label_new ("and");
	gtk_widget_ref (label7);
	gtk_object_set_data_full (GTK_OBJECT (main_window), "label7", label7, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (label7);
	gtk_box_pack_start (GTK_BOX (hbox3), label7, FALSE, FALSE, 0);

	entry5 = gtk_entry_new ();
	gtk_widget_ref (entry5);
	gtk_object_set_data_full (GTK_OBJECT (main_window), "entry5", entry5, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (entry5);
	gtk_box_pack_start (GTK_BOX (hbox3), entry5, TRUE, TRUE, 0);

	label8 = gtk_label_new ("then");
	gtk_widget_ref (label8);
	gtk_object_set_data_full (GTK_OBJECT (main_window), "label8", label8, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (label8);
	gtk_box_pack_start (GTK_BOX (hbox3), label8, FALSE, FALSE, 0);

	optionmenu5 = gtk_option_menu_new ();
	gtk_widget_ref (optionmenu5);
	gtk_object_set_data_full (GTK_OBJECT (main_window), "optionmenu5", optionmenu5, (GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (optionmenu5);
	gtk_box_pack_start (GTK_BOX (hbox3), optionmenu5, FALSE, FALSE, 0);
	optionmenu5_menu = gtk_menu_new ();
	glade_menuitem = gtk_menu_item_new_with_label ("display");
	gtk_widget_show (glade_menuitem);
	gtk_menu_append (GTK_MENU (optionmenu5_menu), glade_menuitem);
	glade_menuitem = gtk_menu_item_new_with_label ("don't display");
	gtk_widget_show (glade_menuitem);
	gtk_menu_append (GTK_MENU (optionmenu5_menu), glade_menuitem);
	gtk_option_menu_set_menu (GTK_OPTION_MENU (optionmenu5), optionmenu5_menu);
	gtk_option_menu_set_history (GTK_OPTION_MENU (optionmenu5), 1);
}

gboolean on_dialog_filters_delete_event(GtkWidget *widget, GdkEvent *event, gpointer user_data)
{
	gtk_widget_hide(dialog_filters);
	return TRUE;
}

void on_button_apply_clicked (GtkButton *button, gpointer user_data)
{
	gtk_widget_hide(dialog_filters);
}

void on_button_cancel_clicked (GtkButton *button, gpointer user_data)
{
	gtk_widget_hide(dialog_filters);
}

/* Callbacks for the main window ------------------------------------------------------------------------------- */

void on_button_search_filter_clicked (GtkButton *button, gpointer user_data)
{
	filters_open_dialog();
}

/* vi: set ts=3: */

