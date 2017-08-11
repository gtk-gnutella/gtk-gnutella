/*
 * Copyright (c) 2001-2003, Richard Eckart
 *
 *----------------------------------------------------------------------
 * This file is part of gtk-gnutella.
 *
 *  gtk-gnutella is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  gtk-gnutella is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with gtk-gnutella; if not, write to the Free Software
 *  Foundation, Inc.:
 *      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *----------------------------------------------------------------------
 */

#ifndef _gtk_gtk_column_chooser_h_
#define _gtk_gtk_column_chooser_h_

#include <gtk/gtk.h>
#include <gtk/gtkmenu.h>
#if (GTK_MAJOR_VERSION >= 2)
#include <gtk/gtktreeview.h>
#else
#include <gtk/gtkclist.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define GTK_COLUMN_CHOOSER(obj)\
     GTK_CHECK_CAST (obj, gtk_column_chooser_get_type (), GtkColumnChooser)
#define GTK_COLUMN_CHOOSER_CLASS(klass)\
     GTK_CHECK_CLASS_CAST (klass, gtk_column_chooser_get_type (), GtkColumnChooserClass)
#define GTK_IS_COLUMN_CHOOSER(obj)\
     GTK_CHECK_TYPE (obj, gtk_column_chooser_get_type ())
#define GTK_TYPE_COLUMN_CHOOSER (gtk_column_chooser_get_type())

typedef struct _GtkColumnChooser GtkColumnChooser;

typedef struct _GtkColumnChooserClass  GtkColumnChooserClass;

struct htable;

struct _GtkColumnChooser {
    GtkMenu menu;

    GtkWidget *widget;
    struct htable *col_map;
    gboolean closed;
};

struct _GtkColumnChooserClass {
    GtkMenuClass parent_class;
};

GtkType gtk_column_chooser_get_type(void);
GtkWidget* gtk_column_chooser_new(GtkWidget *widget);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _gtk_gtk_column_chooser_h_ */

/* vi: set ts=4 sw=4 cindent: */
