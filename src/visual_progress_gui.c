/*
 * $Id$
 *
 * Copyright (c) 2003-2004, Hans de Graaff
 *
 * Displaying the visual progress of downloading graphically.
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


/* 
 * TODO and other ideas to be implemented.
 *
 * Display more information.
 * Automatically move the fastest download to the top of the display.
 */

#include "gui.h"
#include "visual_progress_gui.h"

RCSID("$Id$");

#define VP_PIXELS_PER_ROW 35
#define VP_H_OFFSET 35
#define VP_LINE_BELOW_CHARS 3

/*
 * The context for drawing, including location to draw
 */
typedef struct vp_context {
    GdkDrawable *drawable;
    GdkGC *gc;
    int offset_hor; 
    int offset_ver;
    int width;
    gnet_fi_t fih;
} vp_context_t;

/*
 * Locally cached information from fileinfo needed for drawing the graphics 
 */
typedef struct vp_info {
    gnet_fi_t fi_handle;
    guint row;
    gchar *file_name;
    guint32 file_size;
    GSList *chunks_list;
    vp_context_t *context;
} vp_info_t;

GHashTable *vp_info_hash;  /* Hash table with our cached fileinfo info */

GdkFont *vp_font = NULL;          /* Font to be used in our graphics data */
GdkColor done;           /* Pre-filled color (green) for DONE chunks */
GdkColor done_old;       /* Pre-filled color (dull green) for DONE chunks from previous sessions */
GdkColor busy;           /* Pre-filled color (yellow) for BUSY chunks */
GdkColor empty;              /* Pre-filled color (red) for EMPTY chunks */
GdkColor black;            /* Pre-filled color (black) for general drawing */
static int vp_height = 0;  /* Height of drawing area */

vp_context_t fi_context;
vp_context_t *vp_context;


/* 
 * The graphics routines that do the actual drawing
 */
void vp_draw_chunk (gpointer data, gpointer user_data)
{
    gnet_fi_chunks_t *chunk = data;
    vp_info_t *v = user_data;

    guint s_from;
    guint s_to;
    guint32 bpp;

    if (DL_CHUNK_EMPTY == chunk->status)
	gdk_gc_set_foreground(v->context->gc, &empty);
    if (DL_CHUNK_BUSY == chunk->status)
	gdk_gc_set_foreground(v->context->gc, &busy);
    if (DL_CHUNK_DONE == chunk->status) {
	if (chunk->old)
	    gdk_gc_set_foreground(v->context->gc, &done_old);
	else 
	    gdk_gc_set_foreground(v->context->gc, &done);
    }

    g_assert( v->context->width );
    bpp = v->file_size / (v->context->width - 20);
    s_from = chunk->from / bpp; 
    s_to = chunk->to / bpp; 
    
    /* horizontal offset was 10 */
    gdk_draw_rectangle(v->context->drawable, v->context->gc, TRUE, 
		       s_from + v->context->offset_hor, v->context->offset_ver, 
		       s_to - s_from, 10);
}

void vp_draw_fi (gpointer key, gpointer value, gpointer user_data)
{
    vp_info_t *v = value;
    GString *fakename;

    fakename = g_string_new("");
#ifdef SCREENSHOT_MODE
    g_string_printf(fakename, "<Filename %u>/%s",
		    v->row + 1, compact_size(v->file_size));
#else 
    g_string_printf(fakename, "%s/%s", v->file_name, compact_size(v->file_size));
#endif

    v->context = vp_context;
    v->context->offset_ver = VP_PIXELS_PER_ROW * v->row + VP_H_OFFSET + VP_LINE_BELOW_CHARS;

    gdk_gc_set_foreground(v->context->gc, &black);
    gdk_draw_string(v->context->drawable, vp_font, v->context->gc, 10, VP_H_OFFSET + VP_PIXELS_PER_ROW * v->row, fakename->str);
    g_string_free(fakename, TRUE);

    g_slist_foreach(v->chunks_list, &vp_draw_chunk, v);
}


/* 
 * Draws a progress bar for the given fi struct in the
 * DrawingArea. fih is expected to be a valid fih, or 0 in which case
 * the function returns instead of drawing something.
 */
void vp_draw_fi_progress(gnet_fi_t fih)
{
    vp_info_t *v;
    gpointer atom;

    /*
     * Remember the current fih handle so that we can redraw it later
     */
    fi_context.fih = fih;

    if (fih != -1) {
	g_assert( g_hash_table_lookup_extended(vp_info_hash, &fih, &atom, &v) );
	g_assert( v );

	v->context = &fi_context;

	g_slist_foreach(v->chunks_list, &vp_draw_chunk, v);
    }
}

/* 
 * Callback for the fileinfo pane GtkDrawingArea 
 */
void
on_drawingarea_fi_progress_realize     (GtkWidget       *widget,
                                        gpointer         user_data)
{
    fi_context.drawable = widget->window;
    g_assert( fi_context.drawable );
    fi_context.gc = gdk_gc_new(fi_context.drawable);
    g_assert( fi_context.gc );
    fi_context.offset_hor = 2;
    fi_context.offset_ver = 2;
}

gboolean
on_drawingarea_fi_progress_configure_event
                                        (GtkWidget       *widget,
                                        GdkEventConfigure *event,
                                        gpointer         user_data)
{
    fi_context.width = event->width;

    return FALSE;
}

gboolean
on_drawingarea_fi_progress_expose_event
                                        (GtkWidget       *widget,
                                        GdkEventExpose  *event,
                                        gpointer         user_data)
{
    vp_draw_fi_progress(fi_context.fih);

    return FALSE;
}


/* 
 * Callbacks from the GtkDrawingArea.
 */
void
on_visual_progress_realize             (GtkWidget       *widget,
                                        gpointer         user_data)
{
    /* 
     * The drawing area now exists so we can fill some global
     * variables about drawing.
     */
    vp_context = walloc0(sizeof(vp_context_t));

    vp_context->drawable = widget->window;
    g_assert( vp_context->drawable );

    vp_context->gc = gdk_gc_new(vp_context->drawable);
    g_assert( vp_context->gc );

    vp_context->offset_hor = 10;

    /*
     * TODO: This font loading code is fragile and should be
     * configurable or have a fallback
     */
    vp_font = gdk_font_load("-misc-fixed-medium-r-normal-*-*-120-*-*-*-*-iso8859-1");
    g_assert( vp_font );
    gdk_font_ref(vp_font);

}


gboolean
on_visual_progress_configure_event     (GtkWidget       *widget,
                                        GdkEventConfigure *event,
                                        gpointer         user_data)
{
    g_assert( event );
    g_assert( widget );

    /*
     * We seem to be getting many many configure events. This does not
     * seem to be right, but it is hard to track down where they come
     * from. We could put all kinds of checks in place to see if we
     * really need to act on this configure event, but in the end it
     * is probably easiest to just assign the values without
     * additional checks.
     */

    if (vp_context)
	vp_context->width = event->width;
    vp_height = event->height;

    return FALSE;
}


gboolean
on_visual_progress_expose_event        (GtkWidget       *widget,
                                        GdkEventExpose  *event,
                                        gpointer         user_data)
{
    /*
     * We could be fancy here and parse the expose event for the
     * region to redraw, but it will be more efficient to just draw
     * the whole lot.
     */
    /*
     * TODO: This legend could be a lot more attractive, but I am not
     * sure it will remain
     */
    gdk_gc_set_foreground(vp_context->gc, &black);
    gdk_draw_string(vp_context->drawable, vp_font, vp_context->gc, 10, 15, "Legend: dark green=done    bright green=done recently   white=active   red=empty");

    g_hash_table_foreach(vp_info_hash, &vp_draw_fi, NULL);

    return FALSE;
}


/*
 * A new fileinfo is available. We need to create a cv structure for
 * it, give it a place on the screen, and create the initial graphical
 * representation.
 */
static void vp_gui_fi_added(gnet_fi_t fih)
{
    gnet_fi_info_t *fi = NULL;
    vp_info_t *new_vp_info = NULL;
    gnet_fi_status_t s;

    fi = fi_get_info(fih);
    fi_get_status(fih, &s);
    
    new_vp_info = walloc0(sizeof(*new_vp_info));
    new_vp_info->fi_handle = fih;
    /*
     * TODO: We should initialize the row field in a way that does not
     * depend on fih
     */
    new_vp_info->row = fih;
    new_vp_info->file_name = g_strdup(fi->file_name);
    new_vp_info->file_size = s.size;
    new_vp_info->chunks_list = fi_get_chunks(fih);

    g_hash_table_insert(vp_info_hash, atom_int_get(&fih), new_vp_info);
    
    fi_free_info(fi);
}

static void vp_gui_fi_removed(gnet_fi_t fih)
{
    gpointer *v;
    gpointer atom;
    
    g_assert( g_hash_table_lookup_extended(vp_info_hash, &fih, &atom, &v) );
    g_assert( v );

    /* 
     * TODO: Also remove the row from the GUI and perhaps reshuffle rows
     */

    g_hash_table_remove(vp_info_hash, &fih);
    atom_int_free(atom);
    /* 
     * TODO: Should also probably free the chunks in the list
     */
    g_slist_free( ((vp_info_t *) v)->chunks_list );
    wfree(v, sizeof(vp_info_t));

    /* 
     * Forget the fileinfo handle for which we displayed progress info
     */
    fi_context.fih = -1;
}

/* 
 * Fileinfo has been changed for a file. Update the information and 
 * draw the information so the changes are visible.
 */
static void vp_gui_fi_status_changed(gnet_fi_t fih)
{
    vp_info_t *v;
    gpointer atom;
    GSList *old;
    GSList *new;
    GSList *keep_new;
    gnet_fi_chunks_t *old_chunk;
    gnet_fi_chunks_t * new_chunk;

    /* 
     * TODO: Assuming that only the chunks will change, may not be
     * true...
     */
    g_assert( g_hash_table_lookup_extended(vp_info_hash, &fih, &atom, &v) );
    g_assert( v );

    /* 
     * We will use the new list. We don't just copy it because we want
     * to mark new chunks in the new list as new. So we walk both
     * trees in parallel to make this check, freeing the old list on
     * the way.
     */
    old = v->chunks_list;
    new = fi_get_chunks(fih);
    keep_new = new;
    while (old || new) {
	if (old && new) {
	    old_chunk = (gnet_fi_chunks_t *) old->data;
	    new_chunk = (gnet_fi_chunks_t *) new->data;
	    if (old_chunk->from == new_chunk->from) {
		if (old_chunk->to == new_chunk->to)
		    new_chunk->old = old_chunk->old;
		else
		    new_chunk->old = FALSE;
		wfree(old->data, sizeof(gnet_fi_chunks_t));
		old = g_slist_next(old);
		new = g_slist_next(new);
	    } else {
		if (old_chunk->from < new_chunk->from) {
		    wfree(old->data, sizeof(gnet_fi_chunks_t));
		    old = g_slist_next(old);
		} else {
		    new_chunk->old = FALSE;
		    new = g_slist_next(new);
		}
	    }		    
	} else {
	    /*
	     * Only one list still has nodes, so we just select the
	     * proper next one to advance that list to the end.
	     */
	    if (old) {
		wfree(old->data, sizeof(gnet_fi_chunks_t));
		old = g_slist_next(old);
	    }
	    if (new)
		new = g_slist_next(new);
	}
    }
    g_slist_free(v->chunks_list);
    v->chunks_list = keep_new;

    /*
     * If the graphics have already been set up then also draw the update
     */
    if (vp_context)
	vp_draw_fi(atom, v, NULL);
}

void vp_free_key_value (gpointer key, gpointer value, gpointer user_data)
{
    atom_int_free(key);
    wfree(value, sizeof(vp_info_t));
}

/* 
 * Initialize the use of the canvas: register listeners into the
 * fileinfo structure so that we are notified of fileinfo events, and
 * get a permanent handle to the canvas for later reuse.
 */
void vp_gui_init(void) 
{
    GdkColormap *cmap;

    vp_info_hash = g_hash_table_new(g_int_hash, g_int_equal);

    fi_add_listener((GCallback)vp_gui_fi_added, 
        EV_FI_ADDED, FREQ_SECS, 0);
    fi_add_listener((GCallback)vp_gui_fi_removed, 
        EV_FI_REMOVED, FREQ_SECS, 0);
    fi_add_listener((GCallback)vp_gui_fi_status_changed, 
        EV_FI_STATUS_CHANGED, FREQ_SECS, 0);
    fi_add_listener((GCallback)vp_gui_fi_status_changed, 
        EV_FI_STATUS_CHANGED_TRANSIENT, FREQ_SECS, 0);

    /*
     * TODO: These colors should perhaps be configurable
     */
    cmap = gdk_colormap_get_system();
    g_assert( cmap );
    g_assert(gdk_color_parse("#62ac62", &done_old));
    g_assert(gdk_colormap_alloc_color(cmap, &done_old, FALSE, TRUE));
    g_assert(gdk_color_parse("#62db62", &done));
    g_assert(gdk_colormap_alloc_color(cmap, &done, FALSE, TRUE));
    g_assert(gdk_color_parse("white", &busy));
    g_assert(gdk_colormap_alloc_color(cmap, &busy, FALSE, TRUE));
    g_assert(gdk_color_parse("#d98664", &empty));
    g_assert(gdk_colormap_alloc_color(cmap, &empty, FALSE, TRUE));
    g_assert(gdk_color_parse("black", &black));
    g_assert(gdk_colormap_alloc_color(cmap, &black, FALSE, TRUE));

    /*
     * No progress fih has been seen yet
     */
    fi_context.fih = -1;
}

/* 
 * Undo everything set up in cv_gui_init
 */
void vp_gui_shutdown(void)
{
    fi_remove_listener((GCallback)vp_gui_fi_removed, EV_FI_REMOVED);
    fi_remove_listener((GCallback)vp_gui_fi_added, EV_FI_ADDED);
    fi_remove_listener((GCallback)vp_gui_fi_status_changed, EV_FI_STATUS_CHANGED);

    gdk_font_unref(vp_font);

    g_hash_table_foreach(vp_info_hash, vp_free_key_value, NULL);
    g_hash_table_destroy(vp_info_hash);
}

