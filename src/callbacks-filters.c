#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "gnutella.h"

#include "callbacks-filters.h"
#include "dialog-filters.h"

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

