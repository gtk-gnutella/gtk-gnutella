/*
 * $Id$
 *
 * Copyright (c) 2003, Mike Gray
 *
 * Icon management.
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

#include <gdk/gdk.h>
#include "gnutella.h"
#include "gui.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

static GtkWidget *icon;
static GtkWidget *canvas;
static gboolean icon_visible_fg, icon_just_mapped_fg;
static gint leaf, norm, ultra, con_max;
static gint up_cnt, up_max;
static gint down_cnt, down_max;
static GdkRectangle con_rect, up_rect, down_rect;
static GdkRectangle con_bar, up_bar, down_bar;

static const guint icon_width = 63;
static const guint icon_height = 63;
static const guint icon_inset = 2;
static const guint icon_inset2 = 4;

#if 1
/*
 * XRenderQuerySubpixelOrder
 *
 * I have only "indirectly" installed the gnome-2.0 desktop
 * environment since I really don't use it.  One of the problems
 * this causes is that the shared library libXft.so, which is
 * needed by libpangoxft-1.0.so, which is needed for the gettext
 * functions, can't find this function on my system.  Since I
 * couldn't find a version of libXft.so that would work, and
 * the only recourse seems to be to rebuild the entire xfree
 * package again (of which I don't have the source code right now),
 * I simply define the function here.  Everyone else probably
 * won't need this function.
 */
int XRenderQuerySubpixelOrder(int x, int y)
{
    return 0;
}
#endif

/*
 * get_width
 *
 * Calculates the width of rect will that will represent the
 * value of cnt in rect.
 */
static guint get_width(const GdkRectangle * rect,
                       const guint cnt, const guint mx)
{
    guint width;
    float shift;

    width = rect->width - rect->x;
    shift = ((float) cnt / (float) mx);
    return (guint) ((float) width * shift);
}

/*
 * on_icon_map_event
 *
 * Callback when icon recieves a map event.
 * 
 * This function and on_icon_unmap_event are needed to keep
 * track of when main_window is iconified.
 */
gboolean
on_icon_map_event(GtkWidget * widget, GdkEvent * event, gpointer user_data)
{
    icon_just_mapped_fg = icon_visible_fg = TRUE;
    return FALSE;
}

/*
 * on_icon_unmap_event
 *
 * Callback when icon recieves an unmap event.
 */
gboolean
on_icon_unmap_event(GtkWidget * widget,
                    GdkEvent * event, gpointer user_data)
{
    icon_visible_fg = FALSE;
    return FALSE;
}

/*
 * on_canvas_expose_event
 *
 * Callback when canvas recieves an expose event.
 */
gboolean
on_canvas_expose_event(GtkWidget * widget,
                       GdkEventExpose * event, gpointer user_data)
{
    GdkRectangle rect;

    /* just draw on at a time */
    if (event->count)
        return FALSE;

    /* paint connection bar */
    gtk_paint_shadow(widget->style, widget->window,
                     GTK_STATE_NORMAL, GTK_SHADOW_IN,
                     NULL, widget, NULL,
                     con_rect.x, con_rect.y,
                     con_rect.width, con_rect.height);
    gdk_draw_rectangle(widget->window, widget->style->black_gc, TRUE,
                       con_bar.x, con_bar.y,
                       con_bar.width, con_bar.height);
    rect = con_bar;
    rect.width = get_width(&rect, leaf + norm + ultra, con_max);
    gdk_draw_rectangle(widget->window, widget->style->white_gc, TRUE,
                       rect.x, rect.y, rect.width, rect.height);

    /* paint upload bar */
    gtk_paint_shadow(widget->style, widget->window,
                     GTK_STATE_NORMAL, GTK_SHADOW_IN,
                     NULL, widget, NULL,
                     up_rect.x, up_rect.y, up_rect.width, up_rect.height);
    gdk_draw_rectangle(widget->window, widget->style->black_gc, TRUE,
                       up_bar.x, up_bar.y, up_bar.width, up_bar.height);
    rect = up_bar;
    rect.width = get_width(&rect, up_cnt, up_max);
    gdk_draw_rectangle(widget->window, widget->style->white_gc, TRUE,
                       rect.x, rect.y, rect.width, rect.height);

    /* paint download bar */
    gtk_paint_shadow(widget->style, widget->window,
                     GTK_STATE_NORMAL, GTK_SHADOW_IN,
                     NULL, widget, NULL,
                     down_rect.x, down_rect.y,
                     down_rect.width, down_rect.height);
    gdk_draw_rectangle(widget->window, widget->style->black_gc, TRUE,
                       down_bar.x, down_bar.y,
                       down_bar.width, down_bar.height);
    rect = down_bar;
    rect.width = get_width(&rect, down_cnt, down_max);
    gdk_draw_rectangle(widget->window, widget->style->white_gc, TRUE,
                       rect.x, rect.y, rect.width, rect.height);

    /* paint border */
    gtk_paint_shadow(widget->style, widget->window,
                     GTK_STATE_NORMAL, GTK_SHADOW_OUT,
                     NULL, widget, NULL, 0, 0, -1, -1);

    return FALSE;
}

/*
 * create_icon
 *
 * Sets up the icon and canvas widgets. (Mostly generated by Glade)
 */
static void create_icon(void)
{
    icon = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_widget_set_name(icon, "icon");
    gtk_object_set_data(GTK_OBJECT(icon), "icon", icon);
    gtk_widget_set_usize(icon, icon_width + 1, icon_height + 1);
    gtk_widget_set_sensitive(icon, FALSE);
    GTK_WIDGET_SET_FLAGS(icon, GTK_CAN_FOCUS);
    GTK_WIDGET_SET_FLAGS(icon, GTK_CAN_DEFAULT);
    gtk_widget_set_events(icon, GDK_VISIBILITY_NOTIFY_MASK);
    gtk_window_set_title(GTK_WINDOW(icon), "icon");
    gtk_window_set_default_size(GTK_WINDOW(icon),
                                icon_width + 1, icon_height + 1);
    gtk_window_set_policy(GTK_WINDOW(icon), FALSE, FALSE, FALSE);

    canvas = gtk_drawing_area_new();
    gtk_widget_set_name(canvas, "canvas");
    gtk_widget_ref(canvas);
    gtk_object_set_data_full(GTK_OBJECT(icon), "canvas", canvas,
                             (GtkDestroyNotify) gtk_widget_unref);
    gtk_widget_show(canvas);
    gtk_container_add(GTK_CONTAINER(icon), canvas);
    gtk_widget_set_events(canvas, GDK_EXPOSURE_MASK);

    gtk_signal_connect(GTK_OBJECT(icon), "map_event",
                       GTK_SIGNAL_FUNC(on_icon_map_event), NULL);
    gtk_signal_connect(GTK_OBJECT(icon), "unmap_event",
                       GTK_SIGNAL_FUNC(on_icon_unmap_event), NULL);
    gtk_signal_connect(GTK_OBJECT(canvas), "expose_event",
                       GTK_SIGNAL_FUNC(on_canvas_expose_event), NULL);
}

void icon_timer(void)
{
    GdkRectangle rect;
    GdkEvent event;

    /* Don't do anything if icon isn't even visible */
    if (!icon_visible_fg)
        return;

    /* This may be useful someday */
    if (icon_just_mapped_fg) {
        icon_just_mapped_fg = FALSE;
    }

    /* get current values */
    gnet_prop_get_guint32_val(PROP_NODE_LEAF_COUNT, &leaf);
    gnet_prop_get_guint32_val(PROP_NODE_NORMAL_COUNT, &norm);
    gnet_prop_get_guint32_val(PROP_NODE_ULTRA_COUNT, &ultra);
    gnet_prop_get_guint32_val(PROP_MAX_CONNECTIONS, &con_max);
    gnet_prop_get_guint32_val(PROP_UL_RUNNING, &up_cnt);
    gnet_prop_get_guint32_val(PROP_MAX_UPLOADS, &up_max);
    gnet_prop_get_guint32_val(PROP_DL_RUNNING_COUNT, &down_cnt);
    gnet_prop_get_guint32_val(PROP_MAX_DOWNLOADS, &down_max);

    /*
     * For some reason, gtk_widget_queue_draw(canvas) will
     * not work in either GTK 1 or GTK 2, probably an issue
     * with the fact that the icon window is an icon.  Whatever
     * the reason, to get the canvas widget to redraw, it
     * has to be done that hard way.
     */
    rect.x = rect.y = 0;
    rect.width = canvas->allocation.width;
    rect.height = canvas->allocation.height;

#ifdef USE_GTK2

    gdk_window_invalidate_rect(canvas->window, &rect, FALSE);

#else

    event.type = GDK_EXPOSE;
    event.expose.window = canvas->window;
    event.expose.area = rect;

    /* gtk_propagate_event(canvas) does not work either */
    gtk_widget_event(canvas, &event);

#endif
}

/*
 * For details of what is expected from an icon window and what it 
 * should expect, see --
 *    http://tronche.com/gui/x/icccm/sec-4.html#s-4.1.9
 */
void icon_init(void)
{
    create_icon();
    gtk_widget_realize(icon);

    /*
     * For some reason, when a window is the icon for another
     * window, none of its subwindows get mapped.  This is not
     * because of GTK, but seems to be either the window manager
     * or X itself that does this.
     * Also note the canvas widget is never unmapped, regardless
     * of whether the icon window is visible or not.
     */
    gtk_widget_map(canvas);
    gdk_window_set_icon(main_window->window, icon->window, NULL, NULL);
    icon_just_mapped_fg = icon_visible_fg = FALSE;

    /* setup connection rectangles */
    con_rect.x = 2 + icon_inset;
    con_rect.y = 2 + icon_inset;
    con_rect.width = icon_width - (con_rect.x * 2);
    con_rect.height = 9;
    con_bar = con_rect;
    con_bar.x += icon_inset;
    con_bar.y += icon_inset;
    con_bar.width -= icon_inset2;
    con_bar.height -= icon_inset2;

    /* setup upload rectangles */
    up_rect.x = 2 + icon_inset;
    up_rect.y = 15 + icon_inset;
    up_rect.width = icon_width - (up_rect.x * 2);
    up_rect.height = 9;
    up_bar = up_rect;
    up_bar.x += icon_inset;
    up_bar.y += icon_inset;
    up_bar.width -= icon_inset2;
    up_bar.height -= icon_inset2;

    /* setup downoad rectangles */
    down_rect.x = 2 + icon_inset;
    down_rect.y = 28 + icon_inset;
    down_rect.width = icon_width - (down_rect.x * 2);
    down_rect.height = 9;
    down_bar = down_rect;
    down_bar.x += icon_inset;
    down_bar.y += icon_inset;
    down_bar.width -= icon_inset2;
    down_bar.height -= icon_inset2;
}

void icon_close(void)
{
    icon_visible_fg = FALSE;

    /*
     * Because the icon window is a top level window, it must be
     * destroyed manually.
     */
    gtk_widget_destroy(icon);
}

