/*
 * $Id$
 *
 * Copyright (c) 2001-2002, Richard Eckart
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

#include "uploads_gui.h"

#include "uploads.h" // FIXME: remove this dependency

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

void gui_update_c_uploads(void)
{
    GtkProgressBar *pg = GTK_PROGRESS_BAR
         (lookup_widget(main_window, "progressbar_uploads"));
	gint i = running_uploads;
	gint t = registered_uploads;
    gfloat frac;

	g_snprintf(tmpstr, sizeof(tmpstr), "%u/%u upload%s", i, t,
			   (i == 1 && t == 1) ? "" : "s");

    frac = MIN(i, t) != 0 ? (float)MIN(i, t) / t : 0;

    gtk_progress_bar_set_text(pg, tmpstr);
    gtk_progress_bar_set_fraction(pg, frac);
}

void gui_update_upload(struct upload *u)
{
	gfloat rate = 1, pc = 0;
	guint32 tr = 0;
	gint row;
	gchar tmpstr[256];
	guint32 requested = u->end - u->skip + 1;

	if (u->pos < u->skip)
		return;					/* Never wrote anything yet */

	if (!UPLOAD_IS_COMPLETE(u)) {
		gint slen;
		guint32 bps = 1;
		guint32 avg_bps = 1;

		/*
		 * position divided by 1 percentage point, found by dividing
		 * the total size by 100
		 */
		pc = (u->pos - u->skip) * 100.0 / requested;

		if (u->bio) {
			bps = bio_bps(u->bio);
			avg_bps = bio_avg_bps(u->bio);
		}

		if (avg_bps <= 10 && u->last_update != u->start_date)
			avg_bps = (u->pos - u->skip) / (u->last_update - u->start_date);
		if (avg_bps == 0)
			avg_bps++;

		rate = bps / 1024.0;

		/* Time Remaining at the current rate, in seconds  */
		tr = (u->end + 1 - u->pos) / avg_bps;

		slen = g_snprintf(tmpstr, sizeof(tmpstr), "%.02f%% ", pc);

		if (time((time_t *) 0) - u->last_update > IO_STALLED)
			slen += g_snprintf(&tmpstr[slen], sizeof(tmpstr)-slen,
				"(stalled) ");
		else
			slen += g_snprintf(&tmpstr[slen], sizeof(tmpstr)-slen,
				"(%.1f k/s) ", rate);

		g_snprintf(&tmpstr[slen], sizeof(tmpstr)-slen,
			"TR: %s", short_time(tr));
	} else {
		if (u->last_update != u->start_date) {
			guint32 spent = u->last_update - u->start_date;

			rate = (requested / 1024.0) / spent;
			g_snprintf(tmpstr, sizeof(tmpstr),
				"Completed (%.1f k/s) %s", rate, short_time(spent));
		} else
			g_snprintf(tmpstr, sizeof(tmpstr), "Completed (< 1s)");
	}

    {
        GtkCList *clist_uploads = GTK_CLIST
            (lookup_widget(main_window, "clist_uploads"));

        row = gtk_clist_find_row_from_data(clist_uploads, (gpointer) u);
        gtk_clist_set_text(clist_uploads, row, c_ul_status, tmpstr);
    }
}

