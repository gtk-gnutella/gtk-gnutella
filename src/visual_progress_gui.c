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
 * make colors into properties so that they can be stored in config,
 * should keep hardcoded backups.
 * 
 * Add progress data also to fileinfo table, so that the info is shown for 
 * all current files.
 * 
 * Move the ranges code to fileinfo so that it can be used there as well.
 *
 * Check out why only some requests provide a range
 *
 * Protect against the division by zero errors reported in drawing.
 */

#include "gui.h"
#include "http.h"
#include "downloads.h"
#include "visual_progress_gui.h"

RCSID("$Id$");

#define VP_PIXELS_PER_ROW   35
#define VP_H_OFFSET         35
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
    int height;
    gnet_fi_t fih;
	gboolean fih_valid;
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
	GSList *ranges;
    vp_context_t *context;
} vp_info_t;

GHashTable *vp_info_hash;  /* Hash table with our cached fileinfo info */

GdkFont *vp_font = NULL;   /* Font to be used in our graphics data */
GdkColor done;             /* Pre-filled color (green) for DONE chunks */
GdkColor done_old;         /* Pre-filled color (dull green) for DONE chunks from previous sessions */
GdkColor busy;             /* Pre-filled color (yellow) for BUSY chunks */
GdkColor empty;            /* Pre-filled color (red) for EMPTY chunks */
GdkColor black;            /* Pre-filled color (black) for general drawing */
GdkColor available;        /* Pre-filled color (blue) available on network */
GdkColor *base;            /* Theme-defined background color */

vp_context_t fi_context;
vp_context_t *vp_context;


/* 
 * The graphics routines that do the actual drawing
 */

void vp_draw_rectangle (vp_info_t *v, guint32 from, guint32 to, guint top, guint bottom)
{
    guint32 bpp;
    guint s_from;
    guint s_to;

    g_assert( v );
    g_assert( v->context );
    g_assert( v->context->drawable );

	g_assert( v->context->width );
	g_assert( v->file_size);

    bpp = v->file_size / v->context->width;
    s_from = from / bpp; 
    s_to = to / bpp; 

    gdk_draw_rectangle(v->context->drawable, v->context->gc, TRUE, 
        s_from + v->context->offset_hor, top, 
		s_to - s_from, bottom);
}

void vp_draw_chunk (gpointer data, gpointer user_data)
{
    gnet_fi_chunks_t *chunk = data;
    vp_info_t *v = user_data;

    if (DL_CHUNK_EMPTY == chunk->status)
        gdk_gc_set_foreground(v->context->gc, &empty);
    if (DL_CHUNK_BUSY == chunk->status)
        gdk_gc_set_foreground(v->context->gc, &busy);
    if (DL_CHUNK_DONE == chunk->status) {
        if (chunk->old) {
            gdk_gc_set_foreground(v->context->gc, &done_old);
        } else {
            gdk_gc_set_foreground(v->context->gc, &done);
        }
    }

    vp_draw_rectangle(v, chunk->from, chunk->to, v->context->offset_ver, v->context->height);
}

static void vp_draw_range (gpointer data, gpointer user_data)
{
	http_range_t *range = data;
	vp_info_t *v = user_data;

	gdk_gc_set_foreground(v->context->gc, &available);
	vp_draw_rectangle(v, range->start, range->end, v->context->height - 3, v->context->height);
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
    gdk_draw_string(v->context->drawable, vp_font, v->context->gc, 10, 
        VP_H_OFFSET + VP_PIXELS_PER_ROW * v->row, fakename->str);
    g_string_free(fakename, TRUE);

    g_slist_foreach(v->chunks_list, &vp_draw_chunk, v);
}


/* 
 * Draws a progress bar for the given fi struct in the
 * DrawingArea. fih is expected to be a valid fih. Depending on the
 * value of valid the area will be drawn or cleared.
 */
void vp_draw_fi_progress(gboolean valid, gnet_fi_t fih)
{
    vp_info_t *v;
    gpointer atom;
	gboolean found;

    /*
     * Remember the current fih handle so that we can redraw it later
     */
    fi_context.fih = fih;
	fi_context.fih_valid = valid;

	if (fi_context.drawable) {
		if (valid) {
			found = g_hash_table_lookup_extended(vp_info_hash, &fih, &atom, (gpointer *)&v);
			g_assert( found );
			g_assert( v );
			
			v->context = &fi_context;

			g_slist_foreach(v->chunks_list, &vp_draw_chunk, v);

			g_slist_foreach(v->ranges, &vp_draw_range, v);
		} else {
			gdk_gc_set_foreground(fi_context.gc, base);
			gdk_draw_rectangle(fi_context.drawable, fi_context.gc, TRUE,
							   0, 0, fi_context.width, fi_context.height);
		}
	}
}

/* 
 * Callback for the fileinfo pane GtkDrawingArea 
 */
void
on_drawingarea_fi_progress_realize     (GtkWidget       *widget,
                                        gpointer         user_data)
{
	GtkStyle *style;

    fi_context.drawable = widget->window;
    g_assert( fi_context.drawable );
    fi_context.gc = gdk_gc_new(fi_context.drawable);
    g_assert( fi_context.gc );
    fi_context.offset_hor = 0;
    fi_context.offset_ver = 0;

	style = gtk_widget_get_style(widget);
	base = gdk_color_copy(&(style->base[GTK_STATE_INSENSITIVE]));
}

gboolean
on_drawingarea_fi_progress_configure_event
                                        (GtkWidget       *widget,
                                        GdkEventConfigure *event,
                                        gpointer         user_data)
{
    fi_context.width = event->width;
    fi_context.height = event->height;

    return FALSE;
}

gboolean
on_drawingarea_fi_progress_expose_event
                                        (GtkWidget       *widget,
                                        GdkEventExpose  *event,
                                        gpointer         user_data)
{
	vp_draw_fi_progress(fi_context.fih_valid, fi_context.fih);

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
    gboolean found;

    found = g_hash_table_lookup_extended(vp_info_hash, &fih, &atom, (gpointer *)&v);
    g_assert( found );
    g_assert( v );

    /* 
     * TODO: Also remove the row from the GUI and perhaps reshuffle rows
     */

    g_hash_table_remove(vp_info_hash, &fih);
    atom_int_free(atom);
    fi_free_chunks( ((vp_info_t *) v)->chunks_list );
    
    wfree(v, sizeof(vp_info_t));

    /* 
     * Forget the fileinfo handle for which we displayed progress info
     */
    fi_context.fih_valid = FALSE;
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
    gboolean found;

    /* 
     * TODO: Assuming that only the chunks will change, may not be
     * true...
     */
    found = g_hash_table_lookup_extended(vp_info_hash, &fih, &atom, (gpointer *)&v);
    g_assert( found );
    g_assert( v );

    /* 
     * We will use the new list. We don't just copy it because we want
     * to mark new chunks in the new list as new. So we walk both
     * trees in parallel to make this check.
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
                old = g_slist_next(old);
                new = g_slist_next(new);
            } else {
                if (old_chunk->from < new_chunk->from) {
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
                old = g_slist_next(old);
            }
            if (new)
                new = g_slist_next(new);
        }
    }

	/*
	 * Now that we have checked all old chunks we can discard them 
	 */
    fi_free_chunks(v->chunks_list);
    v->chunks_list = keep_new;

    /*
     * If the graphics have already been set up then also draw the update
     */
    if (vp_context)
        vp_draw_fi(atom, v, NULL);
}


/*
 * Callback for range updates.
 */
static void vp_update_ranges(gnet_src_t srcid)
{
    vp_info_t *v;
    gpointer atom;
	gboolean found;
	gnet_fi_t fih;
	struct download *d;

	d = src_get_download(srcid);
	g_assert( d );

	/* 
	 * Get our own struct associated with this download.
	 */
	fih = d->file_info->fi_handle;
    found = g_hash_table_lookup_extended(vp_info_hash, &fih, &atom, (gpointer *)&v);
    g_assert( found );
    g_assert( v );
	
	fprintf(stderr, "Ranges info for %s\n", d->file_info->file_name);
	fprintf(stderr, "Ranges before: %s\n", http_range_to_gchar(v->ranges));
	fprintf(stderr, "Ranges new   : %s\n", http_range_to_gchar(d->ranges));
	v->ranges = http_range_merge(v->ranges, d->ranges);
	// FIXME: should be freeing old v->ranges list here...
	fprintf(stderr, "Ranges after : %s\n", http_range_to_gchar(v->ranges));
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

	src_add_listener((src_listener_t)vp_update_ranges,
					 EV_SRC_RANGES_CHANGED, FREQ_SECS, 0);

    cmap = gdk_colormap_get_system();
    g_assert( cmap );
    gdk_color_parse("#00DD00", &done_old);
    gdk_colormap_alloc_color(cmap, &done_old, FALSE, TRUE);
    gdk_color_parse("#00FF00", &done);
    gdk_colormap_alloc_color(cmap, &done, FALSE, TRUE);
    gdk_color_parse("#FFFF00", &busy);
    gdk_colormap_alloc_color(cmap, &busy, FALSE, TRUE);
    gdk_color_parse("#FF0000", &empty);
    gdk_colormap_alloc_color(cmap, &empty, FALSE, TRUE);
    gdk_color_parse("black", &black);
    gdk_colormap_alloc_color(cmap, &black, FALSE, TRUE);
	gdk_color_parse("blue", &available);
	gdk_colormap_alloc_color(cmap, &available, FALSE, TRUE);

    /*
     * No progress fih has been seen yet
     */
    fi_context.fih_valid = FALSE;
}

/* 
 * Undo everything set up in cv_gui_init
 */
void vp_gui_shutdown(void)
{
    fi_remove_listener((GCallback)vp_gui_fi_removed, EV_FI_REMOVED);
    fi_remove_listener((GCallback)vp_gui_fi_added, EV_FI_ADDED);
    fi_remove_listener((GCallback)vp_gui_fi_status_changed, EV_FI_STATUS_CHANGED);

	src_remove_listener((src_listener_t)vp_update_ranges, EV_SRC_RANGES_CHANGED);

    gdk_font_unref(vp_font);

    g_hash_table_foreach(vp_info_hash, vp_free_key_value, NULL);
    g_hash_table_destroy(vp_info_hash);
}



/* 
 * Local Variables:
 * tab-width:4
 * End:
 */
