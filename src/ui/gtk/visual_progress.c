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

/**
 * @file
 * 
 * Visual progress indicator for files in the download queue.
 * 
 * TODO and other ideas to be implemented.
 *
 * - The current availability info (blue line) is not accurate,
 * because it only aggregates. It should also take into account when
 * we loose a source. As ram mentioned on IRC: 
 *
 *  right, that's why it's better to construct it dynamically when
 *  needed, and have a "one more alive source", "lost one alive
 *  source" events to update the cached merged list when it's needed
 *  only.
 *
 * make colors into properties so that they can be stored in config,
 * should keep hardcoded backups.
 * 
 * Add progress data also to fileinfo table, so that the info is shown for 
 * all current files.
 * 
 * Move the ranges code to fileinfo so that it can be used there as well.
 *
 * Do not redraw the bar too often, only on event for actual file and
 * perhaps max once a second.
 */

#include "gui.h"

RCSID("$Id$");

#include "visual_progress.h"

#include "if/core/http.h"
#include "if/gui_property_priv.h"
#include "if/bridge/ui2c.h"

#include "lib/walloc.h"
#include "lib/override.h"	/* Must be the last header included */

/**
 * The context for drawing, including location to draw
 */
typedef struct vp_context {
	GtkWidget *widget;     /** The widget containing the drawing area */
    GdkDrawable *drawable; /** The drawable inside the widget */
    GdkGC *gc;             /** The Graphics Context used in this vp context */
    gnet_fi_t fih;         /** The most recently used fileinfo handle */
	gboolean fih_valid;    /** Whether fih is still a valid handle */
} vp_context_t;

/**
 * Locally cached information from fileinfo needed for drawing the graphics 
 */
typedef struct vp_info {
    gnet_fi_t fi_handle;
    gchar *file_name;
    guint32 file_size;
    GSList *chunks_list;
	GSList *ranges_list;
    vp_context_t *context;
} vp_info_t;

static GHashTable *vp_info_hash; /** Hash table with our cached fileinfo info */

static GdkColor done;       /** Pre-filled color (green) for DONE chunks */
static GdkColor done_old;	/** Pre-filled color (dull green) for DONE
							 * chunks from previous sessions */
static GdkColor busy;       /** Pre-filled color (yellow) for BUSY chunks */
static GdkColor empty;      /** Pre-filled color (red) for EMPTY chunks */
static GdkColor black;      /** Pre-filled color (black) for general drawing */
static GdkColor available;  /** Pre-filled color (blue) available on network */
static GdkColor nosize;      /** Pre-filled color (gray) indicates
								 chunk information is not available
								 (e.g. file size == 0 */
static GdkColor *base;      /** Theme-defined background color */

/**
 * The visual progress context for drawing fileinfo information
 */
static vp_context_t fi_context;


/**
 * Draw a rectangle for visual progress
 */
void 
vp_draw_rectangle(vp_info_t *v, guint32 from, guint32 to, 
				  guint top, guint bottom)
{
    guint s_from;
    guint s_to;

    g_assert(v);
    g_assert(v->context);
    g_assert(v->context->drawable);

	/* 
	 * Both these variables should be set to a value, otherwise we get
	 * a division by zero below. We could protect for that, but
	 * neither should be zero when we end up here, so this can be
	 * considered a bug somewhere in the calling code.
	 *
	 * file_size should be set in the fileinfo code. For files with
	 * unknown size the file_size == 0, but in this case
	 * vp_draw_fi_progress catches this case.
	 */
	g_assert(v->file_size);

	s_from = (gfloat) from * v->context->widget->allocation.width 
		/ v->file_size;
	s_to   = (gfloat) to   * v->context->widget->allocation.width 
		/ v->file_size;

    gdk_draw_rectangle(v->context->drawable, v->context->gc, TRUE, 
        s_from, top, s_to - s_from, bottom);
}

/**
 * Draw a chunk for visual progress
 */
void 
vp_draw_chunk (gpointer data, gpointer user_data)
{
    gnet_fi_chunks_t *chunk = data;
    vp_info_t *v = user_data;

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

    vp_draw_rectangle(v,
		chunk->from, chunk->to, 
		0, v->context->widget->allocation.height);
}

static void 
vp_draw_range (gpointer data, gpointer user_data)
{
	http_range_t *range = data;
	vp_info_t *v = user_data;

	gdk_gc_set_foreground(v->context->gc, &available);
	vp_draw_rectangle(v,
		range->start, range->end, 
        v->context->widget->allocation.height - 3, 
        v->context->widget->allocation.height);
}



/**
 * Draws a progress bar for the given fi struct in the DrawingArea. 
 * fih is expected to be a valid fih. Depending on the
 * value of valid the area will be drawn or cleared.
 */
void 
vp_draw_fi_progress(gboolean valid, gnet_fi_t fih)
{
    vp_info_t *v;
	gboolean found;

    /*
     * Remember the current fih handle so that we can redraw it later
     */
    fi_context.fih = fih;
	fi_context.fih_valid = valid;

	if (fi_context.drawable) {
		if (valid) {
			gpointer value;

			found = g_hash_table_lookup_extended(vp_info_hash,
				GUINT_TO_POINTER(fih), NULL, &value);
			g_assert(found);
			g_assert(value);
			
			v = value;
			v->context = &fi_context;

			if (v->file_size > 0) {
				g_slist_foreach(v->chunks_list, &vp_draw_chunk, v);
				g_slist_foreach(v->ranges_list, &vp_draw_range, v);
			} else {
				gdk_gc_set_foreground(fi_context.gc, &nosize);
				gdk_draw_rectangle(fi_context.drawable, fi_context.gc, TRUE,
								   0, 0, 
								   fi_context.widget->allocation.width, 
								   fi_context.widget->allocation.height);
			}
		} else {
			gdk_gc_set_foreground(fi_context.gc, base);
			gdk_draw_rectangle(fi_context.drawable, fi_context.gc, TRUE,
							   0, 0, 
							   fi_context.widget->allocation.width, 
							   fi_context.widget->allocation.height);
		}
	}
}

/** 
 * Callback for the fileinfo pane GtkDrawingArea 
 */
void
on_drawingarea_fi_progress_realize(GtkWidget *widget, gpointer user_data)
{
	GtkStyle *style;

	(void) user_data;
	fi_context.widget = widget;
    fi_context.drawable = widget->window;
    g_assert(fi_context.drawable);
    fi_context.gc = gdk_gc_new(fi_context.drawable);
    g_assert(fi_context.gc);

	style = gtk_widget_get_style(widget);
	base = gdk_color_copy(&(style->base[GTK_STATE_INSENSITIVE]));
}

gboolean
on_drawingarea_fi_progress_expose_event(
	GtkWidget *widget, GdkEventExpose *event, gpointer user_data)
{
	(void) widget;
	(void) event;
	(void) user_data;
	vp_draw_fi_progress(fi_context.fih_valid, fi_context.fih);

    return FALSE;
}


/*
 * A new fileinfo is available. We need to create a cv structure for
 * it, give it a place on the screen, and create the initial graphical
 * representation.
 */
static void 
vp_gui_fi_added(gnet_fi_t fih)
{
    gnet_fi_info_t *fi = NULL;
    vp_info_t *new_vp_info = NULL;
    gnet_fi_status_t s;

    fi = guc_fi_get_info(fih);
    guc_fi_get_status(fih, &s);
    
    new_vp_info = walloc0(sizeof(*new_vp_info));
    new_vp_info->fi_handle = fih;
    new_vp_info->file_name = g_strdup(fi->file_name);
    new_vp_info->file_size = s.size;
    new_vp_info->chunks_list = guc_fi_get_chunks(fih);
	new_vp_info->ranges_list = guc_fi_get_ranges(fih);

    g_hash_table_insert(vp_info_hash, GUINT_TO_POINTER(fih), new_vp_info);
    
    guc_fi_free_info(fi);
}

/**
 * Handle the event that a fileinfo entry has been removed
 *
 * @param fih The fileinfo handle of the entry to be removed
 */
static void 
vp_gui_fi_removed(gnet_fi_t fih)
{
    gpointer value;
    gboolean found;
	vp_info_t *v;

    found = g_hash_table_lookup_extended(vp_info_hash,
		GUINT_TO_POINTER(fih), NULL, &value);
    g_assert(found);
    g_assert(value);
	v = value;

    g_hash_table_remove(vp_info_hash, GUINT_TO_POINTER(fih));

    guc_fi_free_chunks(v->chunks_list);
	G_FREE_NULL(v->file_name);

    wfree(v, sizeof(vp_info_t));

    /* Forget the fileinfo handle for which we displayed progress info */
    fi_context.fih_valid = FALSE;
}

/* 
 * Fileinfo has been changed for a file. Update the information and 
 * draw the information so the changes are visible.
 */
static void 
vp_gui_fi_status_changed(gnet_fi_t fih)
{
    vp_info_t *v;
    GSList *old;
    GSList *new;
    GSList *keep_new;
    gnet_fi_chunks_t *old_chunk;
    gnet_fi_chunks_t * new_chunk;
    gboolean found;
	gpointer value;

    found = g_hash_table_lookup_extended(vp_info_hash,
		GUINT_TO_POINTER(fih), NULL, &value);
    g_assert(found);
    g_assert(value);
	v = value;

    /* 
	 * Copy the chunks.
     * We will use the new list. We don't just copy it because we want
     * to mark new chunks in the new list as new. So we walk both
     * trees in parallel to make this check.
     */
    old = v->chunks_list;
    new = guc_fi_get_chunks(fih);
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
            if (old)
                old = g_slist_next(old);
            if (new)
                new = g_slist_next(new);
        }
    }

	/*
	 * Now that we have checked all old chunks we can discard them 
	 */
    guc_fi_free_chunks(v->chunks_list);
    v->chunks_list = keep_new;
	
	/*
	 * Copy the ranges. These can simply be copied as we do not need to 
	 * apply our own logic to them.
	 */
	guc_fi_free_ranges(v->ranges_list);
	v->ranges_list = guc_fi_get_ranges(fih);
}


/**
 * Free the vp_info_t structs in the vp_info_hash
 */
void 
vp_free_key_value (gpointer key, gpointer value, gpointer user_data)
{
	(void) key;
	(void) user_data;
    guc_fi_free_chunks(((vp_info_t *) value)->chunks_list);
	G_FREE_NULL(((vp_info_t *) value)->file_name);
    wfree(value, sizeof(vp_info_t));
}

/* 
 * Initialize the use of the canvas: register listeners into the
 * fileinfo structure so that we are notified of fileinfo events, and
 * get a permanent handle to the canvas for later reuse.
 */
void 
vp_gui_init(void) 
{
    GdkColormap *cmap;

    vp_info_hash = g_hash_table_new(NULL, NULL);

    guc_fi_add_listener(vp_gui_fi_added, EV_FI_ADDED, 
		FREQ_SECS, 0);
    guc_fi_add_listener(vp_gui_fi_removed, EV_FI_REMOVED, 
		FREQ_SECS, 0);
    guc_fi_add_listener(vp_gui_fi_status_changed, 
		EV_FI_STATUS_CHANGED, FREQ_SECS, 0);
    guc_fi_add_listener(vp_gui_fi_status_changed, 
		EV_FI_STATUS_CHANGED_TRANSIENT, FREQ_SECS, 0);

	cmap = gdk_colormap_get_system();
    g_assert(cmap);
    gdk_color_parse("green4", &done_old);
    gdk_colormap_alloc_color(cmap, &done_old, FALSE, TRUE);
    gdk_color_parse("green", &done);
    gdk_colormap_alloc_color(cmap, &done, FALSE, TRUE);
    gdk_color_parse("yellow2", &busy);
    gdk_colormap_alloc_color(cmap, &busy, FALSE, TRUE);
    gdk_color_parse("red2", &empty);
    gdk_colormap_alloc_color(cmap, &empty, FALSE, TRUE);
    gdk_color_parse("black", &black);
    gdk_colormap_alloc_color(cmap, &black, FALSE, TRUE);
	gdk_color_parse("blue", &available);
	gdk_colormap_alloc_color(cmap, &available, FALSE, TRUE);
	gdk_color_parse("gray", &nosize);
	gdk_colormap_alloc_color(cmap, &nosize, FALSE, TRUE);

    /*
     * No progress fih has been seen yet
     */
    fi_context.fih_valid = FALSE;
}

/**
 * Undo everything set up in vp_gui_init
 */
void 
vp_gui_shutdown(void)
{
    guc_fi_remove_listener(vp_gui_fi_removed, EV_FI_REMOVED);
    guc_fi_remove_listener(vp_gui_fi_added, EV_FI_ADDED);
    guc_fi_remove_listener(vp_gui_fi_status_changed, 
		EV_FI_STATUS_CHANGED);

    g_hash_table_foreach(vp_info_hash, vp_free_key_value, NULL);
    g_hash_table_destroy(vp_info_hash);
}




/* 
 * Local Variables:
 * tab-width:4
 * End:
 * vi: set ts=4:
 */
