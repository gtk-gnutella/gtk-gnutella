/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Raphael Manfredi, Richard Eckart
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

#include "downloads_gui.h"

#define IO_STALLED		60		/* If nothing exchanged after that many secs */

static gchar tmpstr[4096];

void gui_update_upload_kill(void)
{
	GList *l = NULL;
	struct upload *d = NULL;
    GtkCList *clist = GTK_CLIST
        (lookup_widget(main_window, "clist_uploads"));

	for (l = clist->selection; l; l = l->next) {
		d = (struct upload *) gtk_clist_get_row_data(clist, (gint) l->data);
		if (UPLOAD_IS_COMPLETE(d)) {
			d = NULL;
			break;
		}
	}

	gtk_widget_set_sensitive
        (lookup_widget(main_window, "button_uploads_kill"), d ? 1 : 0);
}



void gui_update_download_clear(void)
{
	GSList *l;
	gboolean clear = FALSE;

	for (l = sl_unqueued; !clear && l; l = l->next) {
		switch (((struct download *) l->data)->status) {
		case GTA_DL_COMPLETED:
		case GTA_DL_ERROR:
		case GTA_DL_ABORTED:
			clear = TRUE;
			break;
		default:
			break;
		}
	}

	gtk_widget_set_sensitive(
        lookup_widget(main_window, "button_downloads_clear_completed"), 
        clear);
}

void gui_update_download(struct download *d, gboolean force)
{
	gchar *a = NULL;
	gint row;
	time_t now = time((time_t *) NULL);
    GdkColor *color;
    GtkCList *clist_downloads;

    if (d->last_gui_update == now && !force)
		return;

    clist_downloads = GTK_CLIST
        (lookup_widget(main_window, "clist_downloads"));

    color = &(gtk_widget_get_style(GTK_WIDGET(clist_downloads))
        ->fg[GTK_STATE_INSENSITIVE]);

	d->last_gui_update = now;

	switch (d->status) {
	case GTA_DL_QUEUED:
		a = (gchar *) ((d->remove_msg) ? d->remove_msg : "");
		break;

	case GTA_DL_CONNECTING:
		a = "Connecting...";
		break;

	case GTA_DL_PUSH_SENT:
		a = "Push sent";
		break;

	case GTA_DL_REQ_SENT:
		a = "Request sent";
		break;

	case GTA_DL_HEADERS:
		a = "Receiving headers";
		break;

	case GTA_DL_ABORTED:
		a = "Aborted";
		break;

	case GTA_DL_FALLBACK:
		a = "Falling back to push";
		break;

	case GTA_DL_COMPLETED:
		if (d->last_update != d->start_date) {
			guint32 spent = d->last_update - d->start_date;

			gfloat rate = ((d->range_end - d->skip + d->overlap_size) /
				1024.0) / spent;
			g_snprintf(tmpstr, sizeof(tmpstr), "%s (%.1f k/s) %s",
				FILE_INFO_COMPLETE(d->file_info) ? "Completed" : "Chunk done",
				rate, short_time(spent));
		} else {
			g_snprintf(tmpstr, sizeof(tmpstr), "%s (< 1s)",
				FILE_INFO_COMPLETE(d->file_info) ? "Completed" : "Chunk done");
		}
		a = tmpstr;
		break;

	case GTA_DL_RECEIVING:
		if (d->pos - d->skip > 0) {
			gfloat p = 0, pt = 0;
			gint bps;
			guint32 avg_bps;

			if (d->size)
                p = (d->pos - d->skip) * 100.0 / d->size;
            if (download_filesize(d))
                pt = download_filedone(d) * 100.0 / download_filesize(d);

			bps = bio_bps(d->bio);
			avg_bps = bio_avg_bps(d->bio);

			if (avg_bps <= 10 && d->last_update != d->start_date)
				avg_bps = (d->pos - d->skip) / (d->last_update - d->start_date);

			if (avg_bps) {
				gint slen;
				guint32 s;
				gfloat bs;

                if (d->size > (d->pos - d->skip))
                    s = (d->size - (d->pos - d->skip)) / avg_bps;
                else
                    s=0;

				bs = bps / 1024.0;

				slen = g_snprintf(tmpstr, sizeof(tmpstr),
					"%.02f%% / %.02f%% ", p, pt);

				if (now - d->last_update > IO_STALLED)
					slen += g_snprintf(&tmpstr[slen], sizeof(tmpstr)-slen,
						"(stalled) ");
				else
					slen += g_snprintf(&tmpstr[slen], sizeof(tmpstr)-slen,
						"(%.1f k/s) ", bs);

				g_snprintf(&tmpstr[slen], sizeof(tmpstr)-slen,
					"TR: %s", s ? short_time(s) : "-");
			} else
				g_snprintf(tmpstr, sizeof(tmpstr), "%.02f%%%s", p,
					(now - d->last_update > IO_STALLED) ? " (stalled)" : "");

			a = tmpstr;
		} else
			a = "Connected";
		break;

	case GTA_DL_ERROR:
		a = (gchar *) ((d->remove_msg) ? d->remove_msg : "Unknown Error");
		break;

	case GTA_DL_TIMEOUT_WAIT:
		{
			gint when = d->timeout_delay - (now - d->last_update);
			g_snprintf(tmpstr, sizeof(tmpstr), "Retry in %ds", MAX(0, when));
		}
		a = tmpstr;
		break;
	default:
		g_snprintf(tmpstr, sizeof(tmpstr), "UNKNOWN STATUS %u",
				   d->status);
		a = tmpstr;
	}

	if (d->status != GTA_DL_TIMEOUT_WAIT)
		d->last_gui_update = now;

	if (d->status != GTA_DL_QUEUED) {
		row = gtk_clist_find_row_from_data(clist_downloads, (gpointer) d);
		gtk_clist_set_text(clist_downloads, row, c_dl_status, a);
        if (DOWNLOAD_IS_IN_PUSH_MODE(d))
             gtk_clist_set_foreground(clist_downloads, row, color);
	}
    if (d->status == GTA_DL_QUEUED) {
        GtkCList *clist_downloads_queue = GTK_CLIST
            (lookup_widget(main_window, "clist_downloads_queue"));

		row = gtk_clist_find_row_from_data
            (clist_downloads_queue, (gpointer) d);
		gtk_clist_set_text(clist_downloads_queue, row, c_queue_status, a);
        if (d->always_push)
             gtk_clist_set_foreground(clist_downloads_queue, row, color);
	}
}

void gui_update_download_server(struct download *d)
{
	gint row;
    GtkCList *clist_downloads = GTK_CLIST
            (lookup_widget(main_window, "clist_downloads"));

	g_assert(d);
	g_assert(d->status != GTA_DL_QUEUED);
	g_assert(d->server);
	g_assert(download_vendor(d));

	row = gtk_clist_find_row_from_data(clist_downloads,	(gpointer) d);
	gtk_clist_set_text(clist_downloads, row, c_dl_server, download_vendor(d));
}

void gui_update_download_range(struct download *d)
{
	guint32 len;
	gchar *and_more = "";
	gint rw;
	gint row;
    GtkCList *clist_downloads = GTK_CLIST
            (lookup_widget(main_window, "clist_downloads"));

	g_assert(d);
	g_assert(d->status != GTA_DL_QUEUED);

	if (d->file_info->use_swarming) {
		len = d->size;
		if (d->range_end > d->skip + d->size)
			and_more = "+";
	} else
		len = d->range_end - d->skip;

	len += d->overlap_size;

	rw = g_snprintf(tmpstr, sizeof(tmpstr), "%s%s",
		compact_size(len), and_more);

	if (d->skip)
		g_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw, " @ %s",
			compact_size(d->skip));

	row = gtk_clist_find_row_from_data(clist_downloads,	(gpointer) d);
	gtk_clist_set_text(clist_downloads, row, c_dl_range, tmpstr);
}
