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

