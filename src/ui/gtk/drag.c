/*
 * Copyright (c) 2007, Christian Biere
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

/**
 * @ingroup gtk
 * @file
 *
 * Drag support - no dropping, just dragging.
 *
 * @author Christian Biere
 * @date 2007
 */

#include "gui.h"

#include "drag.h"

#include "lib/override.h"		/* Must be the last header included */

/*
 * Public functions
 */

struct drag_context {
	drag_get_data_cb get_data;
	gboolean uri_list;
};

/**
 * Allocates a new drag context, to be freed with drag_free().
 * @return a drag context.
 */
static struct drag_context *
drag_alloc(void)
{
	static const struct drag_context zero_ctx;
	struct drag_context *ctx;

	ctx = g_malloc(sizeof *ctx);
	*ctx = zero_ctx;
	return ctx;
}

/**
 * Frees a drag context.
 */
static void
drag_free(struct drag_context **ptr)
{
	struct drag_context *ctx = *ptr;

	if (ctx) {
		ctx->get_data = NULL;
		G_FREE_NULL(ctx);
		*ptr = NULL;
	}
}

#if GTK_CHECK_VERSION(2,0,0)
gboolean
drag_get_iter(GtkTreeView *tv, GtkTreeModel **model, GtkTreeIter *iter)
{
	gboolean ret = FALSE;
	GtkTreePath *path;

	g_return_val_if_fail(model, FALSE);
	g_return_val_if_fail(iter, FALSE);

	gtk_tree_view_get_cursor(tv, &path, NULL);
	if (path) {
		*model = gtk_tree_view_get_model(tv);
		ret = gtk_tree_model_get_iter(*model, iter, path);
		gtk_tree_path_free(path);
	}
	return ret;
}

#define object_ref(obj)		g_object_ref((obj))
#define object_unref(obj)	g_object_unref((obj))


static inline void
selection_set_data(GtkSelectionData *data, const char *text, gboolean uri_list)
{
	if (uri_list) {
		const char *uris[2];

		uris[0] = text;
		uris[1] = NULL;
		gtk_selection_data_set_uris(data, (char **) uris);
	} else {
		size_t len;

		len = text ? strlen(text) : 0;
		len = len < INT_MAX ? len : 0;
		gtk_selection_data_set_text(data, text, len);
	}
}

#else	/* Gtk < 2 */

#define object_ref(obj)		gtk_object_ref(GTK_OBJECT(obj))
#define object_unref(obj)	gtk_object_unref(GTK_OBJECT(obj))

static inline void
selection_set_data(GtkSelectionData *data, const char *text, gboolean uri_list)
{
	size_t len;

	(void) uri_list;
	/* FIXME: Figure out how to support text/uri-list with Gtk+ 1.2 */
	len = text ? strlen(text) : 0;
	len = len < INT_MAX ? len : 0;
   	gtk_selection_data_set(data, GDK_SELECTION_TYPE_STRING, 8 /* CHAR_BIT */,
		cast_to_gconstpointer(text), len);
}

#endif /* Gtk+ >= 2 */

static void
drag_begin(GtkWidget *widget, GdkDragContext *unused_drag_ctx, void *udata)
{
	struct drag_context *ctx = udata;

	(void) unused_drag_ctx;

	gui_signal_stop_emit_by_name(widget, "drag-begin");

	g_return_if_fail(ctx);
	g_return_if_fail(ctx->get_data);
}


static void
drag_data_get(GtkWidget *widget, GdkDragContext *unused_drag_ctx,
	GtkSelectionData *data, unsigned unused_info, unsigned unused_stamp,
	void *udata)
{
	struct drag_context *ctx = udata;
	char *text;

	(void) unused_drag_ctx;
	(void) unused_info;
	(void) unused_stamp;

	gui_signal_stop_emit_by_name(widget, "drag-data-get");

	g_return_if_fail(ctx);
	g_return_if_fail(ctx->get_data);

	text = ctx->get_data(widget);
	selection_set_data(data, text, ctx->uri_list);
	G_FREE_NULL(text);
}

static void
drag_end(GtkWidget *widget, GdkDragContext *unused_drag_ctx, void *udata)
{
	struct drag_context *ctx = udata;

	(void) unused_drag_ctx;

	gui_signal_stop_emit_by_name(widget, "drag-end");

	g_return_if_fail(ctx);
	g_return_if_fail(ctx->get_data);
}

static void
destroy(GtkObject *widget, void *udata)
{
	struct drag_context *ctx = udata;

	g_return_if_fail(ctx);
	g_return_if_fail(ctx->get_data);

	gui_signal_disconnect(widget, drag_data_get, ctx);
	gui_signal_disconnect(widget, drag_begin, ctx);
	gui_signal_disconnect(widget, drag_end, ctx);
	gui_signal_disconnect(widget, destroy, ctx);

	drag_free(&ctx);
	object_unref(widget);
}

/**
 * Attaches a drag context to a widget, so that user can drag data from
 * the widget as text. The context can be attached to multiple widgets.
 */
static void
drag_attach(GtkWidget *widget, drag_get_data_cb callback, gboolean uri_list)
{
    static const GtkTargetEntry text_targets[] = {
#if GTK_CHECK_VERSION(2,0,0)
        { "UTF8_STRING",				0, 1 },
        { "text/plain;charset=utf-8",	0, 2 },
#endif	/* Gtk+ >= 2.0 */
        { "STRING",						0, 3 },
        { "text/plain",					0, 4 },
	};
    static const GtkTargetEntry uri_targets[] = {
        { "text/uri-list",				0, 5 },
    };
	struct drag_context *ctx;
    const GtkTargetEntry *targets;
	unsigned num_targets;

	g_return_if_fail(widget);
	g_return_if_fail(callback);

	object_ref(widget);
	ctx = drag_alloc();
	ctx->get_data = callback;
	ctx->uri_list = uri_list;

	if (uri_list) {
		targets = uri_targets;
		num_targets = G_N_ELEMENTS(uri_targets);
	} else {
		targets = text_targets;
		num_targets = G_N_ELEMENTS(text_targets);
	}

	/* Initialize drag support */
	gtk_drag_source_set(widget,
		GDK_BUTTON1_MASK | GDK_BUTTON2_MASK, targets, num_targets,
		GDK_ACTION_DEFAULT | GDK_ACTION_COPY | GDK_ACTION_ASK);

    gui_signal_connect(widget, "drag-data-get", drag_data_get, ctx);
    gui_signal_connect(widget, "drag-begin",	drag_begin, ctx);
    gui_signal_connect(widget, "drag-end",	  	drag_end, ctx);
    gui_signal_connect(widget, "destroy",		destroy, ctx);
}

void
drag_attach_text(GtkWidget *widget, drag_get_data_cb callback)
{
	drag_attach(widget, callback, FALSE);
}

void
drag_attach_uri(GtkWidget *widget, drag_get_data_cb callback)
{
	drag_attach(widget, callback, TRUE);
}
/* vi: set ts=4 sw=4 cindent: */
