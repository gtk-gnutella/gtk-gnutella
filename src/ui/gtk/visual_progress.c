/*
 * Copyright (c) 2003-2005, Hans de Graaff
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
 * Displaying the visual progress of downloading graphically.
 *
 * Visual progress indicator for files in the download queue.
 *
 * @todo Make colors into properties so that they can be stored in config,
 *       should keep hardcoded backups.
 * @todo Add progress data also to fileinfo table, so that the info is shown 
 *       for all current files.
 * @todo Do not redraw the bar too often, only on event for actual file and
 *       perhaps max once a second.
 *
 * @author Hans de Graaff
 * @date 2003-2005
 */

#include "gui.h"

#include "visual_progress.h"
#include "downloads_common.h"	/* For fi_gui_fi_status_changed() */

#include "if/core/http.h"
#include "if/gui_property_priv.h"
#include "if/bridge/ui2c.h"

#include "lib/atoms.h"
#include "lib/htable.h"
#include "lib/stringify.h"
#include "lib/walloc.h"
#include "lib/override.h"	/* Must be the last header included */

/** The height of the indicator arrows in visual progress */
#define VP_ARROW_HEIGHT 7

/**
 * The context for drawing, including location to draw.
 */
typedef struct vp_context {
	GtkWidget *widget;      /**< The widget containing the drawing area */
    GdkDrawable *drawable;  /**< The drawable inside the widget */
    GdkGC *gc;              /**< The Graphics Context used in this vp context */
    gnet_fi_t fih;          /**< The most recently used fileinfo handle */
	gboolean fih_valid;	    /**< Whether fih is still a valid handle */
} vp_context_t;

/**
 * Locally cached information from fileinfo needed for drawing the graphics.
 */
typedef struct vp_info {
    gnet_fi_t fi_handle;
    const gchar *filename;		/* atom */
    GSList *chunks_list;
	GSList *chunks_initial;
	GSList *ranges_list;
    vp_context_t *context;
    filesize_t filesize;
	filesize_t done_initial;
} vp_info_t;

static htable_t *vp_info_hash; /**< Hash table with our cached fileinfo info */

static struct {
	GdkColor base;      /**< Theme-defined background color */
	GdkColor done;       /**< Pre-filled color (green) for DONE chunks */
	GdkColor done_old;	/**< Pre-filled color (dull green) for DONE
								 chunks from previous sessions */
	GdkColor busy;       /**< Pre-filled color (yellow) for BUSY chunks */
	GdkColor arrow;      /**< Pre-filled color (blue) for start of BUSY */
	GdkColor empty;      /**< Pre-filled color (red) for EMPTY chunks */
	GdkColor black;      /**< Pre-filled color (black) for general drawing */
	GdkColor available;  /**< Pre-filled color (blue) available on network */
	GdkColor nosize;     /**< Pre-filled color (gray) indicates
								 chunk information is not available
								 (e.g. file size == 0 */
} colors;

/**
 * The visual progress context for drawing fileinfo information.
 */
static vp_context_t fi_context;


/**
 * Draw a rectangle for visual progress.
 */
void
vp_draw_rectangle(vp_info_t *v, filesize_t from, filesize_t to,
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
	 * filesize should be set in the fileinfo code. For files with
	 * unknown size the filesize == 0, but in this case
	 * vp_draw_fi_progress catches this case.
	 */
	g_assert(v->filesize > 0);

	s_from = (1.0 * from * v->context->widget->allocation.width)
		/ v->filesize;
	s_to   = (1.0 * to   * v->context->widget->allocation.width)
		/ v->filesize;

    gdk_draw_rectangle(v->context->drawable, v->context->gc, TRUE,
        s_from, top, s_to - s_from, bottom);
}

/**
 * Draw a chunk for visual progress.
 */
static void
vp_draw_chunk(gpointer data, gpointer user_data)
{
    gnet_fi_chunks_t *chunk = data;
    vp_info_t *v = user_data;

    if (DL_CHUNK_EMPTY == chunk->status)
        gdk_gc_set_foreground(v->context->gc, &colors.empty);
    if (DL_CHUNK_BUSY == chunk->status)
        gdk_gc_set_foreground(v->context->gc, &colors.busy);
    if (DL_CHUNK_DONE == chunk->status) {
        if (chunk->old)
            gdk_gc_set_foreground(v->context->gc, &colors.done_old);
        else
            gdk_gc_set_foreground(v->context->gc, &colors.done);
    }

    vp_draw_rectangle(v,
		chunk->from, chunk->to,
		0, v->context->widget->allocation.height);
}

/**
 * Draw an downward arrow starting at the top.
 */
static void
vp_draw_arrow(vp_info_t *v, filesize_t at)
{
	guint s_at;
	GdkPoint points[3];

    g_assert(v);
    g_assert(v->context);
    g_assert(v->context->drawable);

	g_assert(v->filesize);

	s_at = (1.0 * at * v->context->widget->allocation.width) / v->filesize;

	/* Fill the inside of the arrow */
	points[0].x = s_at - VP_ARROW_HEIGHT;
	points[0].y = 0;
	points[1].x = s_at;
	points[1].y = VP_ARROW_HEIGHT;
	points[2].x = s_at + VP_ARROW_HEIGHT;
	points[2].y = 0;
	gdk_gc_set_foreground(v->context->gc, &colors.arrow);
	gdk_draw_polygon(v->context->drawable, v->context->gc,
		TRUE, points, G_N_ELEMENTS(points));

	/* Draw a black border around the arrow */
	gdk_gc_set_foreground(v->context->gc, &colors.black);
	gdk_draw_polygon(v->context->drawable, v->context->gc,
		FALSE, points, G_N_ELEMENTS(points));
}

/**
 * Draw arrows on the start of BUSY chunks to make them stand out.
 * This is done in a separate funtion, because the arrows need to be
 * drawn on top of the chunks.
 */
static void
vp_draw_arrows(gpointer data, gpointer user_data)
{
    gnet_fi_chunks_t *chunk = data;
    vp_info_t *v = user_data;

	if (DL_CHUNK_BUSY == chunk->status)
		vp_draw_arrow(v, chunk->from);
}

/**
 * Draw an available range. Callback for a list iterator.
 *
 * @param data       The HTTP range to draw.
 * @param user_data  A pointer to the vp_info_t structure.
 */
static void
vp_draw_range (gpointer data, gpointer user_data)
{
	http_range_t *range = data;
	vp_info_t *v = user_data;

	gdk_gc_set_foreground(v->context->gc, &colors.available);
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

			found = htable_lookup_extended(vp_info_hash,
				uint_to_pointer(fih), NULL, &value);
    		g_return_if_fail(found);
			g_assert(value);

			v = value;
			v->context = &fi_context;

			if (v->filesize > 0) {
				g_slist_foreach(v->chunks_list, vp_draw_chunk, v);
				g_slist_foreach(v->chunks_list, vp_draw_arrows, v);
				g_slist_foreach(v->ranges_list, vp_draw_range, v);
			} else {
				gdk_gc_set_foreground(fi_context.gc, &colors.nosize);
				gdk_draw_rectangle(fi_context.drawable, fi_context.gc, TRUE,
								   0, 0,
								   fi_context.widget->allocation.width,
								   fi_context.widget->allocation.height);
			}
		} else {
			gdk_gc_set_foreground(fi_context.gc, &colors.base);
			gdk_draw_rectangle(fi_context.drawable, fi_context.gc, TRUE,
							   0, 0,
							   fi_context.widget->allocation.width,
							   fi_context.widget->allocation.height);
		}
	}
}

/**
 * Callback for the fileinfo pane GtkDrawingArea.
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
	colors.base = style->base[GTK_STATE_INSENSITIVE];
}

/**
 * Callback for the fileinfo pane GtkDrawingArea.
 */
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

/**
 * Get a list of chunks and filter out all empty chunks for quicker
 * handling later on. Returns pointer to the new list. Caller should
 * make sure to free this list and its chunks.
 *
 * @param fih  Fileinfo handle for which chunks should be retrieved
 */
static GSList *
vp_get_chunks_initial(gnet_fi_t fih) {

	GSList *result, *sl, *prev = NULL;

	result = guc_fi_get_chunks(fih);

	for (sl = result; sl; /* NOTHING */) {
		gnet_fi_chunks_t *chunk = sl->data;
		GSList *next;

		next = g_slist_next(sl);
		if (DL_CHUNK_DONE != chunk->status) {
			if (prev) {
				prev = g_slist_delete_link(prev, sl);
			} else {
				result = g_slist_delete_link(result, sl);
			}
			WFREE(chunk);
		} else {
			prev = sl;
		}
		sl = next;
	}

	return result;
}

/**
 * A new fileinfo is available. We need to create a structure for it
 * and store all relevant information.
 *
 * @param fih The fileinfo handle of the entry being added.
 */
static void
vp_gui_fi_added(gnet_fi_t fih)
{
    gnet_fi_info_t *fi;
    vp_info_t *new_vp_info;
    gnet_fi_status_t s;

    fi = guc_fi_get_info(fih);
    guc_fi_get_status(fih, &s);

    WALLOC0(new_vp_info);
    new_vp_info->fi_handle = fih;
    new_vp_info->filename = atom_str_get(fi->filename);
    new_vp_info->filesize = s.size;
    new_vp_info->chunks_list = guc_fi_get_chunks(fih);
	new_vp_info->ranges_list = guc_fi_get_ranges(fih);

	/*
	 * Keep an optimized copy of the initial chunks list. Also
	 * remember the amount of data already downloaded. This helps to
	 * detect cheaply if the file download had restarted due to SHA1
	 * mismatch.
	 */
	new_vp_info->chunks_initial = vp_get_chunks_initial(fih);
	new_vp_info->done_initial = s.done;

    htable_insert(vp_info_hash, uint_to_pointer(fih), new_vp_info);

    guc_fi_free_info(fi);
}

static void
vp_info_free(vp_info_t **v_ptr)
{
	g_assert(v_ptr);

	if (*v_ptr) {
		vp_info_t *v = *v_ptr;
		
		guc_fi_free_chunks(v->chunks_list);
		guc_fi_free_chunks(v->chunks_initial);
		guc_fi_free_ranges(v->ranges_list);
		atom_str_free_null(&v->filename);
		WFREE(v);
		*v_ptr = NULL;
	}
}

/**
 * Handle the event that a fileinfo entry has been removed.
 *
 * @param fih The fileinfo handle of the entry to be removed
 */
static void
vp_gui_fi_removed(gnet_fi_t fih)
{
    gpointer value;
    gboolean found;
	vp_info_t *v;

    found = htable_lookup_extended(vp_info_hash,
		uint_to_pointer(fih), NULL, &value);
	g_return_if_fail(found);
    g_assert(value);

	v = value;
    htable_remove(vp_info_hash, uint_to_pointer(fih));
	vp_info_free(&v);

    /* Forget the fileinfo handle for which we displayed progress info */
    fi_context.fih_valid = FALSE;
}

/**
 * For debugging: print chunk.
 */
static void
vp_print_chunk(FILE *file, const gnet_fi_chunks_t *c, gboolean show_old)
{
	if (show_old)
		fprintf(file, "%10s - %10s %d [%s]\n",
			uint64_to_string(c->from), uint64_to_string2(c->to),
			(gint) c->status, c->old ? "O" : "N");
	else
		fprintf(file, "%10s - %10s %d\n",
			uint64_to_string(c->from), uint64_to_string2(c->to),
			(gint) c->status);
}

/**
 * For debugging: print chunk list.
 */
static void
vp_print_chunk_list(FILE *file, const GSList *list, const gchar *title)
{
	const GSList *sl;

	fprintf(file, "Chunk list \"%s\":\n", title);

	for (sl = list; sl; sl = g_slist_next(sl)) {
		const gnet_fi_chunks_t *c = sl->data;
		vp_print_chunk(file, c, FALSE);
	}

	fprintf(file, "End of list \"%s\".\n", title);
}

/**
 * Allocate a new chunk based on the parameters.
 *
 * @param from   Start of chunk
 * @param to     End of chunk
 * @param status Status of chunk
 * @param old    TRUE if the chunk was downloaded before gtk-gnutella is started
 */
static gnet_fi_chunks_t *
vp_create_chunk(filesize_t from, filesize_t to,
	enum dl_chunk_status status, gboolean old)
{
	gnet_fi_chunks_t *chunk;

	WALLOC(chunk);
	chunk->from = from;
	chunk->to = to;
	chunk->status = status;
	chunk->old = old;

#ifdef VP_DEBUG
	printf("VP adding: ");
	vp_print_chunk(stdout, chunk, TRUE);
#endif /* VP_DEBUG */

	return chunk;
}

/**
 * Assert that a chunks list confirms to the assumptions.
 */
static gboolean
vp_assert_chunks_list(const GSList *list, const gnet_fi_info_t *fi)
{
	const GSList *sl;
	filesize_t last = 0;

	for (sl = list; sl; sl = g_slist_next(sl)) {
		const gnet_fi_chunks_t *chunk = sl->data;

		if (last != chunk->from) {
			g_warning("BAD CHUNK LIST for \"%s\"", fi->filename);
			vp_print_chunk_list(stderr, list, "Chunks list");
			return FALSE;
		}
		last = chunk->to;
	}
	return TRUE;
}

/**
 * Fileinfo has been changed for a file. Update the information and
 * draw the information so the changes are visible.
 *
 * @param fih Handle for fileinfo data that has been changed.
 */
static void
vp_gui_fi_status_changed(gnet_fi_t fih)
{
    vp_info_t *v;
    GSList *old;
    GSList *new;
    GSList *keep_new;
    gnet_fi_chunks_t *oc;
    gnet_fi_chunks_t *nc;
    gboolean found;
	gpointer value;
	filesize_t highest = 0;
	gnet_fi_info_t *fi;
	gnet_fi_status_t s;

    found = htable_lookup_extended(vp_info_hash,
		uint_to_pointer(fih), NULL, &value);
	g_return_if_fail(found);
    g_assert(value);
	v = value;

	/*
	 * Check for the case that there is less data downloaded now
	 * compared to when we started. This indicates that the download
	 * has been started from scratch. In this case we re-initialize
	 * the chunks_initial list and done field to keep the visual
	 * display accurate.
	 */
	fi = guc_fi_get_info(fih);
	guc_fi_get_status(fih, &s);
	if (v->done_initial > s.done) {
		guc_fi_free_chunks(v->chunks_initial);
		v->chunks_initial = vp_get_chunks_initial(fih);
		v->done_initial = s.done;
	}

	/*
	 * Use the new chunks list to create a composite with the initial
	 * chunks. This way the previously downloaded chunks can be kept
	 * intact.
	 */
	old = v->chunks_initial;
	new = guc_fi_get_chunks(fih);
	keep_new = new;	/* So that we can free this list later */

	/*
	 * Check if this chunks list is valid. If not then skip building a
	 * new list, and do housekeeping stuff here.
	 */
	if (!vp_assert_chunks_list(new, fi)) {
		guc_fi_free_chunks(keep_new);
		goto cleanup;
	}

	guc_fi_free_chunks(v->chunks_list);
	v->chunks_list = NULL;

	while (old || new) {
		if (old && new) {
			oc = old->data;
			nc = new->data;

			/*
			 * Skip over chunks below the highest mark, they are no longer
			 * relevant.
			 *
			 * NB: the `old' list is NOT a contiguous list, but stores
			 * only completed chunks.  The `new' list is contiguous though.
			 */

			if (oc->to <= highest) {
				old = g_slist_next(old);
				continue;
			}
			if (nc->to <= highest) {
				new = g_slist_next(new);
				continue;
			}

			/*
			 * Check for contiguous list. A failed assertion here
			 * indicates problems in the algorithm.
			 */
			g_assert(nc->from == highest);

			/*
			 * The chunks are identical: nothing changed, copy one chunk
			 */
			if (oc->from == nc->from && oc->to == nc->to) {
				highest = nc->to;
				v->chunks_list = g_slist_append(v->chunks_list,
				    vp_create_chunk(nc->from, nc->to, nc->status, TRUE));
				old = g_slist_next(old);
				new = g_slist_next(new);
				continue;
			}

			/*
			 * If one of the chunks fits completely before the other we
			 * copy it and skip to the next chunk. This will only happen
			 * for chunks in the new list.
			 */
			if (oc->from >= nc->to) {
				highest = nc->to;
				v->chunks_list = g_slist_append(v->chunks_list,
 					vp_create_chunk(nc->from, nc->to, nc->status, FALSE));
				new = g_slist_next(new);
				continue;
			}

			/*
			 * This is the case where chunks overlap. The chunks will need
			 * to be split in their old and new parts.
			 */
			if (oc->from > nc->from) {
				/* Create a new chunk in front of the old chunk */
				v->chunks_list = g_slist_append(v->chunks_list,
					vp_create_chunk(nc->from, oc->from, nc->status, FALSE));
			}
			highest = oc->to;
			/*
			 * The old chunk can be copied into the list now, but
			 * there is one special case we need to make: it may be
			 * that the new chunk is actually smaller than the old one
			 * because we had to back out some data, e.g. on a resume
			 * mismatch.
			 */
			if (oc->from >= nc->from && oc->to <= nc->to)
				v->chunks_list = g_slist_append(v->chunks_list,
				    vp_create_chunk(oc->from, oc->to, oc->status, TRUE));
			else {
				/*
				 * The new chunk we are considering covers a smaller
				 * area than the old chunk, so some data got lost. To
				 * cope with this we follow two paths.
				 */
				if (nc->status == DL_CHUNK_DONE && nc->to >= oc->to)
					/*
					 * In this case we copy the old part of the done
					 * chunk here, and the new extended part
					 * below. This is why we do not continue here.
					 */
					v->chunks_list = g_slist_append(v->chunks_list,
						vp_create_chunk(nc->from, oc->to, nc->status, TRUE));
				else {
					/*
					 * In this case we copy the chunk and skip
					 * it. Depending on the situation the next
					 * iteration will deal with the remainder of this
					 * overlap, or skip the old chunk, depending on
					 * whether nc->to is larger than oc->to.
					 */
					v->chunks_list = g_slist_append(v->chunks_list,
						vp_create_chunk(nc->from, nc->to, nc->status, TRUE));
					highest = nc->to;
					new = g_slist_next(new);
					continue;
				}
			}
			if (oc->to < nc->to) {
				highest = nc->to;
				v->chunks_list = g_slist_append(v->chunks_list,
					vp_create_chunk(oc->to, nc->to, nc->status, FALSE));
			}

			old = g_slist_next(old);
			new = g_slist_next(new);
		} else {
			/*
			 * If only old or new chunks are left then just copy them onto
			 * the chunks list.
			 */
			if (old) {
				oc = old->data;
				v->chunks_list = g_slist_append(v->chunks_list,
					vp_create_chunk(oc->from, oc->to, oc->status, TRUE));
				old = g_slist_next(old);
			}

			if (new) {
				nc = new->data;
				v->chunks_list = g_slist_append(v->chunks_list,
					vp_create_chunk(nc->from, nc->to, nc->status, FALSE));
				new = g_slist_next(new);
			}
		}
	}

	/*
	 * Now that the new list of chunks is merged with the old chunks we
	 * can safely throw away the new list itself.
	 */
	guc_fi_free_chunks(keep_new);

cleanup:
	guc_fi_free_info(fi);
}


/**
 * The available ranges information has been changed for a
 * file. Update the information and draw the information so the
 * changes are visible.
 *
 * @param fih Handle for fileinfo data that has been changed.
 */
static void
vp_gui_fi_ranges_changed(gnet_fi_t fih)
{
    vp_info_t *v;
    gboolean found;
	gpointer value;

    found = htable_lookup_extended(vp_info_hash,
		uint_to_pointer(fih), NULL, &value);
    g_return_if_fail(found);
    g_assert(value);
	v = value;

	/*
	 * Copy the ranges. These can simply be copied as we do not need to
	 * apply our own logic to them.
	 */
	guc_fi_free_ranges(v->ranges_list);
	v->ranges_list = guc_fi_get_ranges(fih);

	fi_gui_fi_status_changed(fih);		/* Enqueue re-drawing event */
}


/**
 * Free the vp_info_t structs in the vp_info_hash.
 */
static void
vp_free_key_value(const void *key, void *value, void *user_data)
{
	vp_info_t *v = value;

	(void) key;
	(void) user_data;

	vp_info_free(&v);
}

/**
 * Initialize the use of visual progress.
 *
 * Register listeners into the fileinfo structure so that we are
 * notified of fileinfo events, and get a permanent handle to the
 * drawing area for later reuse.
 */
G_GNUC_COLD void
vp_gui_init(void)
{
    GdkColormap *cmap;

    vp_info_hash = htable_create(HASH_KEY_SELF, 0);

    guc_fi_add_listener(vp_gui_fi_added, EV_FI_ADDED,
		FREQ_SECS, 0);
    guc_fi_add_listener(vp_gui_fi_removed, EV_FI_REMOVED,
		FREQ_SECS, 0);
    guc_fi_add_listener(vp_gui_fi_status_changed,
		EV_FI_STATUS_CHANGED, FREQ_SECS, 0);
    guc_fi_add_listener(vp_gui_fi_status_changed,
		EV_FI_STATUS_CHANGED_TRANSIENT, FREQ_SECS, 0);
    guc_fi_add_listener(vp_gui_fi_ranges_changed,
						EV_FI_RANGES_CHANGED, FREQ_SECS, 0);

	cmap = gdk_colormap_get_system();
    g_assert(cmap);
    gdk_color_parse("green4", &colors.done_old);
    gdk_colormap_alloc_color(cmap, &colors.done_old, FALSE, TRUE);
    gdk_color_parse("green", &colors.done);
    gdk_colormap_alloc_color(cmap, &colors.done, FALSE, TRUE);
    gdk_color_parse("yellow2", &colors.busy);
    gdk_colormap_alloc_color(cmap, &colors.busy, FALSE, TRUE);
	gdk_color_parse("light sky blue", &colors.arrow);
	gdk_colormap_alloc_color(cmap, &colors.arrow, FALSE, TRUE);
    gdk_color_parse("red2", &colors.empty);
    gdk_colormap_alloc_color(cmap, &colors.empty, FALSE, TRUE);
    gdk_color_parse("black", &colors.black);
    gdk_colormap_alloc_color(cmap, &colors.black, FALSE, TRUE);
	gdk_color_parse("blue", &colors.available);
	gdk_colormap_alloc_color(cmap, &colors.available, FALSE, TRUE);
	gdk_color_parse("gray", &colors.nosize);
	gdk_colormap_alloc_color(cmap, &colors.nosize, FALSE, TRUE);

    /*
     * No progress fih has been seen yet
     */
    fi_context.fih_valid = FALSE;
}

/**
 * Undo everything set up in vp_gui_init.
 */
G_GNUC_COLD void
vp_gui_shutdown(void)
{
    guc_fi_remove_listener(vp_gui_fi_removed, EV_FI_REMOVED);
    guc_fi_remove_listener(vp_gui_fi_added, EV_FI_ADDED);
    guc_fi_remove_listener(vp_gui_fi_status_changed, EV_FI_STATUS_CHANGED);
    guc_fi_remove_listener(vp_gui_fi_status_changed,
		EV_FI_STATUS_CHANGED_TRANSIENT);
    guc_fi_remove_listener(vp_gui_fi_ranges_changed, EV_FI_RANGES_CHANGED);

    htable_foreach(vp_info_hash, vp_free_key_value, NULL);
    htable_free_null(&vp_info_hash);
}

/*
 * Local Variables:
 * tab-width:4
 * End:
 * vi: set ts=4 sw=4 cindent:
 */
