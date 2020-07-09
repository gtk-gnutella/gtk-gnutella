/*
 * Copyright (c) 2004, Russell Francis
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup gtk
 * @file
 *
 * GTK+ cell renderer.
 *
 * @author Russell Francis
 * @date 2004
 *
 * @note
 * gtkcellrenderer.c
 *
 * Copyright (C) 2002 Naba Kumar <kh_naba@users.sourceforge.net>
 * heavily modified by Joergen Scheibengruber <mfcn@gmx.de>
 * and yet more modifications by Russell Francis <rf358197@ohiou.edu>
 *
 * Originally found in gnome-system-monitor and imported Jan 2004. It
 * may be useful to check for updates in the upstream version every
 * now and then.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "gtk/gui.h"

#include "pbarcellrenderer.h"

#if defined(USING_CUSTOM_TYPE_CELL_RENDERER_PROGRESS)
/*
 * This widget is included in GTK+ since 2.5.0
 */

#include "lib/str.h"

#include "lib/override.h"		/* Must be the last header included */

static void gtk_cell_renderer_progress_init(GtkCellRendererProgress *);

static void gtk_cell_renderer_progress_class_init(
	GtkCellRendererProgressClass *);

static void gtk_cell_renderer_progress_finalize(GObject *);

static void gtk_cell_renderer_progress_get_property(
	GObject *,
	guint,
	GValue *,
	GParamSpec *);

static void gtk_cell_renderer_progress_set_property(
	GObject *,
	guint,
	const GValue *,
	GParamSpec *);

static void gtk_cell_renderer_progress_get_size(
	GtkCellRenderer *,
	GtkWidget *,
	GdkRectangle *,
	gint *,					/* x_offset */
	gint *,					/* y_offset */
	gint *,					/* width */
    gint *);				/* height */

static void gtk_cell_renderer_progress_render(
	GtkCellRenderer *,
	GdkWindow *,
	GtkWidget *,
	GdkRectangle *,			/* background area */
	GdkRectangle *,			/* cell area */
	GdkRectangle *,			/* expose area */
	GtkCellRendererState);	/* flags */

/*
 * Properties that this widget can have manipulated.
 */
enum {
  PROP_0,		/**< Placeholder, empty property */
  PROP_VALUE	/**< The position of the progress bar [0:100] */
};

struct _GtkCellRendererProgressPriv {
	gint value;
};

static gpointer parent_class;


/**
 * Register the new type 'gtk_cell_renderer_progress' with
 * the GTK type system and return the unique integer id
 * associated with this type.
 *
 * @return A unique GtkType id
 */
GtkType
gtk_cell_renderer_progress_get_type(void)
{
	static GtkType cell_progress_type = 0;

	if (!cell_progress_type) {
		static const GTypeInfo cell_progress_info =
		{
			sizeof (GtkCellRendererProgressClass),
			NULL,		/* base_init */
			NULL,		/* base_finalize */
			(GClassInitFunc) gtk_cell_renderer_progress_class_init,
			NULL,		/* class_finalize */
			NULL,		/* class_data */
			sizeof (GtkCellRendererProgress),
			0,      	/* n_preallocs */
			(GInstanceInitFunc) gtk_cell_renderer_progress_init,
			NULL
		};

		cell_progress_type = g_type_register_static(
			GTK_TYPE_CELL_RENDERER,
			"GtkCellRendererProgress",
            &cell_progress_info,
			0);
	}

	return cell_progress_type;
}


/**
 * Initialize the progress bar private data.
 *
 * @param cellprogress The GtkCellRendererProgress to init.
 *
 * @return nothing
 */
static void
gtk_cell_renderer_progress_init(GtkCellRendererProgress *cellprogress)
{
    WALLOC0(cellprogress->priv);
}

/**
 * Initialize the progress bar class data.
 *
 * @param class The GtkCellRendererProgressClass - internal
 *
 * @return nothing
 */
static void
gtk_cell_renderer_progress_class_init (GtkCellRendererProgressClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS(class);
	GtkCellRendererClass *cell_class = GTK_CELL_RENDERER_CLASS(class);

	parent_class = g_type_class_peek_parent(class);

	object_class->finalize = gtk_cell_renderer_progress_finalize;

	object_class->get_property = gtk_cell_renderer_progress_get_property;
	object_class->set_property = gtk_cell_renderer_progress_set_property;

	cell_class->get_size = gtk_cell_renderer_progress_get_size;
	cell_class->render = gtk_cell_renderer_progress_render;

	g_object_class_install_property(
		object_class,
		PROP_VALUE,
		g_param_spec_int (
			"value",
			"Value",
			"Value of the progress bar.",
			0, 100, 0,
			G_PARAM_READWRITE));
}


/**
 * This retreives the value of a property which the object widget has.
 *
 * @param object The object to get a property of.
 * @param param_id The id of the property we wish to get.
 * @param value Where we should store the value of the property.
 * @param pspec The Param Specification of the property.
 *
 * @return nothing
 */
static void
gtk_cell_renderer_progress_get_property(
	GObject *object,
	guint param_id,
	GValue *value,
	GParamSpec *pspec)
{
	GtkCellRendererProgress *cellprogress = GTK_CELL_RENDERER_PROGRESS(object);

	switch (param_id) {
	case PROP_VALUE:
		g_value_set_int(value, cellprogress->priv->value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID(object, param_id, pspec);
	}
}


/**
 * gtk_cell_renderer_progress_set_property
 *
 * Set a property of the given gtk_cell_renderer_progress
 * widget.
 *
 * @param object The object to set a property on.
 * @param param_id The parameter id we wish to change.
 * @param value The value we should assign to the property.
 * @param pspec The GParamSpec for this property.
 *
 * @return nothing
 */
static void
gtk_cell_renderer_progress_set_property(
	GObject *object,
	guint param_id,
	const GValue *value,
	GParamSpec *pspec)
{
	GtkCellRendererProgress *cellprogress = GTK_CELL_RENDERER_PROGRESS(object);

	switch (param_id) {
	case PROP_VALUE:
		cellprogress->priv->value = g_value_get_int(value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID(object, param_id, pspec);
	}
	g_object_notify (object, "value");
}


/**
 * gtk_cell_renderer_progress_get_size
 *
 * Get the size of the cell here.
 *
 * @param unused_cell The GtkCellRenderer we are getting the size of.
 * @param unused_widget
 * @param unused_cell_area The cell area that we have.
 * @param unused_x_offset The xoffset for the packed widget.
 * @param unused_y_offset The yoffset for the packed widget.
 * @param width The minimum width of the widget.
 * @param height The minimum height of the widget.
 *
 * @return nothing
 */
static void
gtk_cell_renderer_progress_get_size(
	GtkCellRenderer *unused_cell,
	GtkWidget       *unused_widget,
	GdkRectangle    *unused_cell_area,
	gint            *unused_x_offset,
	gint            *unused_y_offset,
	gint            *width,
	gint            *height)
{
	(void) unused_cell;
	(void) unused_widget;
	(void) unused_cell_area;
	(void) unused_x_offset;
	(void) unused_y_offset;

	/*
	 * Always return 1 here. Doesn't make to much sense,
	 * but providing the real width would make it
	 * impossible for the bar to shrink again.
	 */
	if (width)
		*width = 1;
	if (height)
		*height = 1;
}


/**
 * gtk_cell_renderer_progress_new
 *
 * Create a new cell renderer progress bar ready to
 * stuff in a treeview.
 *
 * @return a GtkCellRenderer * for your use.
 */
GtkCellRenderer* gtk_cell_renderer_progress_new(void)
{
	return GTK_CELL_RENDERER(
		g_object_new(gtk_cell_renderer_progress_get_type(), NULL));
}


/**
 * gtk_cell_renderer_progress_render
 *
 * Physically draw the progress bar in our
 * assigned space.
 *
 * @param cell The cell renderer we wish to draw.
 * @param window The GdkWindow we will draw in.
 * @param widget The widget that we derive style attr. from.
 * @param unused_background_area The background rectangle.
 * @param cell_area The rectange for the cell.
 * @param unused_expose_area The area which received an expose event.
 * @param unused_flags flags...
 *
 * @return nothing
 */
static void
gtk_cell_renderer_progress_render(
	GtkCellRenderer *cell,
	GdkWindow *window,
	GtkWidget *widget,
	GdkRectangle *unused_background_area,
	GdkRectangle *cell_area,
	GdkRectangle *unused_expose_area,
	GtkCellRendererState unused_flags)
{
	GtkCellRendererProgress *cellprogress = (GtkCellRendererProgress *) cell;
	GtkStateType state;
	GdkGC *gc;
	PangoLayout *layout;
	PangoRectangle logical_rect;
	char text[32];
	int x, y, w, h, perc_w, pos;
	int val;

	(void) unused_background_area;
	(void) unused_expose_area;
	(void) unused_flags;

	gc = gdk_gc_new(window);

	x = cell_area->x + 4;
	y = cell_area->y + 2;
	w = cell_area->width - 8;
	h = cell_area->height - 4;

	gdk_gc_set_rgb_fg_color(gc, &widget->style->fg[GTK_STATE_NORMAL]);
	gdk_draw_rectangle(window, gc, TRUE, x, y, w, h);

	gdk_gc_set_rgb_fg_color(gc, &widget->style->bg[GTK_STATE_NORMAL]);
	gdk_draw_rectangle(window, gc, TRUE, x + 1, y + 1, w - 2, h - 2);
	gdk_gc_set_rgb_fg_color(gc, &widget->style->bg[GTK_STATE_SELECTED]);
	perc_w = (int)((w - 4) * (cellprogress->priv->value / 100.0));
	gdk_draw_rectangle(window, gc, TRUE, x + 2, y + 2, perc_w, h - 4);

	val = cellprogress->priv->value;
	str_bprintf(ARYLEN(text), "%d", val);
	layout = gtk_widget_create_pango_layout(widget, text);
	pango_layout_get_pixel_extents(layout, NULL, &logical_rect);
	g_object_unref(G_OBJECT (layout));
	str_bprintf(ARYLEN(text), "%d %%", val);
	layout = gtk_widget_create_pango_layout(widget, text);

	pos = (w - logical_rect.width) / 2;

	if (perc_w < pos + logical_rect.width / 2)
		state = GTK_STATE_NORMAL;
	else
		state = GTK_STATE_SELECTED;

	gtk_paint_layout(
		widget->style,
		window,
		state,
		FALSE,
		cell_area,
		widget,
		"progressbar",
		x + pos,
		y + (h - logical_rect.height) / 2,
		layout);

	g_object_unref(G_OBJECT(layout));
	g_object_unref(G_OBJECT(gc));
}

/**
 * gtk_cell_renderer_progress_finalize
 *
 * Finalize the object.
 *
 * @param object The object which we will finalize.
 *
 * @return nothing
 */
static void
gtk_cell_renderer_progress_finalize(GObject *object)
{
	GtkCellRendererProgress *cellprogress = GTK_CELL_RENDERER_PROGRESS(object);
	WFREE(cellprogress->priv);
	cellprogress->priv = NULL;
	(*G_OBJECT_CLASS(parent_class)->finalize)(object);
}

#endif /* !USING_CUSTOM_TYPE_CELL_RENDERER_PROGRESS */

/* vi: set ts=4 sw=4 cindent: */
