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

#include "downloads.h" /* FIXME: remove this dependency */
#include "dmesh.h" /* FIXME: remove this dependency */
#include "statusbar_gui.h"
#include "downloads_cb.h"
#include "parq.h"

RCSID("$Id$");

#define IO_STALLED		60		/* If nothing exchanged after that many secs */
#define IO_AVG_RATE		5		/* Compute global recv rate every 5 secs */

static gchar tmpstr[4096];

void gui_update_download_clear(void)
{
	GSList *l;
	gboolean clear = FALSE;

	for (l = sl_unqueued; !clear && l; l = l->next) {
		switch (((struct download *) l->data)->status) {
		case GTA_DL_COMPLETED:
		case GTA_DL_ERROR:
		case GTA_DL_ABORTED:
		case GTA_DL_DONE:
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
	const gchar *a = NULL;
	gint row;
	time_t now = time((time_t *) NULL);
    GdkColor *color;
    GtkCList *clist_downloads;
	struct dl_file_info *fi;
	gint rw;
	extern gint sha1_eq(gconstpointer a, gconstpointer b);

    if (d->last_gui_update == now && !force)
		return;

    clist_downloads = GTK_CLIST
        (lookup_widget(main_window, "clist_downloads"));

    color = &(gtk_widget_get_style(GTK_WIDGET(clist_downloads))
        ->fg[GTK_STATE_INSENSITIVE]);

	d->last_gui_update = now;
	fi = d->file_info;

	switch (d->status) {
	case GTA_DL_ACTIVE_QUEUED:	/* JA, 31 jan 2003 Active queueing */
		{
			time_t elapsed = now - d->last_update;

			rw = gm_snprintf(tmpstr, sizeof(tmpstr), "Queued");

			if (get_parq_dl_position(d) > 0) {

				rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					" (slot %d",		/* ) */
					get_parq_dl_position(d));
				
				if (get_parq_dl_queue_length(d) > 0) {
					rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
						" / %d", get_parq_dl_queue_length(d));
				}

				if (get_parq_dl_eta(d)  > 0) {
					rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
						", ETA: %s",
						short_time((get_parq_dl_eta(d)  - elapsed)));
				}

				rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw, /* ( */ ")");
			}

			rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					" retry in %ds",
					(gint) (get_parq_dl_retry_delay(d) - elapsed));
		}
		a = tmpstr;
		break;
	case GTA_DL_QUEUED:
		a = d->remove_msg ? d->remove_msg : "";
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
			gm_snprintf(tmpstr, sizeof(tmpstr), "%s (%.1f k/s) %s",
				FILE_INFO_COMPLETE(fi) ? "Completed" : "Chunk done",
				rate, short_time(spent));
		} else {
			gm_snprintf(tmpstr, sizeof(tmpstr), "%s (< 1s)",
				FILE_INFO_COMPLETE(fi) ? "Completed" : "Chunk done");
		}
		a = tmpstr;
		break;

	case GTA_DL_VERIFY_WAIT:
		g_assert(FILE_INFO_COMPLETE(fi));
		gm_snprintf(tmpstr, sizeof(tmpstr), "Waiting for SHA1 checking...");
		a = tmpstr;
		break;

	case GTA_DL_VERIFYING:
		g_assert(FILE_INFO_COMPLETE(fi));
		gm_snprintf(tmpstr, sizeof(tmpstr),
			"Computing SHA1 (%.02f%%)", fi->cha1_hashed * 100.0 / fi->size);
		a = tmpstr;
		break;

	case GTA_DL_VERIFIED:
	case GTA_DL_MOVE_WAIT:
	case GTA_DL_MOVING:
	case GTA_DL_DONE:
		g_assert(FILE_INFO_COMPLETE(fi));
		g_assert(fi->cha1_hashed <= fi->size);
		{
			gboolean sha1_ok = fi->cha1 &&
				(fi->sha1 == NULL || sha1_eq(fi->sha1, fi->cha1));

			rw = gm_snprintf(tmpstr, sizeof(tmpstr), "SHA1 %s %s",
				fi->sha1 == NULL ? "figure" : "check",
				fi->cha1 == NULL ?	"ERROR" :
				sha1_ok ?			"OK" :
									"FAILED");
			if (fi->cha1 && fi->cha1_hashed) {
				time_t elapsed = fi->cha1_elapsed;
				rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					" (%.1f k/s) %s",
					(gfloat) (fi->cha1_hashed >> 10) / (elapsed ? elapsed : 1),
					short_time(fi->cha1_elapsed));
			}

			switch (d->status) {
			case GTA_DL_MOVE_WAIT:
				gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					"; Waiting for moving...");
				break;
			case GTA_DL_MOVING:
				gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					"; Moving (%.02f%%)", fi->copied * 100.0 / fi->size);
				break;
			case GTA_DL_DONE:
				if (fi->copy_elapsed) {
					gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
						"; Moved (%.1f k/s) %s",
						(gfloat) (fi->copied >> 10) / fi->copy_elapsed,
						short_time(fi->copy_elapsed));
				}
				break;
			default:
				break;
			}
		}
		a = tmpstr;
		break;

	case GTA_DL_RECEIVING:
		if (d->pos - d->skip > 0) {
			gfloat p = 0, pt = 0;
			gint bps;
			guint32 avg_bps;

			/*
			 * Update the global average reception rate periodically.
			 */

			g_assert(fi->recvcount > 0);

			if (now - fi->recv_last_time > IO_AVG_RATE) {
				fi->recv_last_rate =
					fi->recv_amount / (now - fi->recv_last_time);
				fi->recv_amount = 0;
				fi->recv_last_time = now;
			}

			if (d->size)
                p = (d->pos - d->skip) * 100.0 / d->size;
            if (download_filesize(d))
                pt = download_filedone(d) * 100.0 / download_filesize(d);

			bps = bio_bps(d->bio);
			avg_bps = bio_avg_bps(d->bio);

			if (avg_bps <= 10 && d->last_update != d->start_date)
				avg_bps = (d->pos - d->skip) / (d->last_update - d->start_date);

			rw = 0;

			if (avg_bps) {
				guint32 remain = 0;
				guint32 s;
				gfloat bs;

                if (d->size > (d->pos - d->skip))
                    remain = d->size - (d->pos - d->skip);

                s = remain / avg_bps;
				bs = bps / 1024.0;

				rw = gm_snprintf(tmpstr, sizeof(tmpstr),
					"%.02f%% / %.02f%% ", p, pt);

				if (now - d->last_update > IO_STALLED)
					rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
						"(stalled) ");
				else
					rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
						"(%.1f k/s) ", bs);

				rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					"[%d/%d] TR: %s", fi->recvcount, fi->lifecount,
					s ? short_time(s) : "-");

				if (fi->recv_last_rate) {
					s = (fi->size - fi->done) / fi->recv_last_rate;

					rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
						" / %s", short_time(s));

					if (fi->recvcount > 1) {
						bs = fi->recv_last_rate / 1024.0;

						rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
							" (%.1f k/s)", bs);
					}
				}
			} else
				rw = gm_snprintf(tmpstr, sizeof(tmpstr), "%.02f%%%s", p,
					(now - d->last_update > IO_STALLED) ? " (stalled)" : "");

			/*
			 * If source is a partial source, show it.
			 */

			if (d->ranges != NULL)
				gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					" <PFS %.02f%%>", d->ranges_size * 100.0 / fi->size);

			a = tmpstr;
		} else
			a = "Connected";
		break;

	case GTA_DL_ERROR:
		a = d->remove_msg ? d->remove_msg : "Unknown Error";
		break;

	case GTA_DL_TIMEOUT_WAIT:
		{
			gint when = d->timeout_delay - (now - d->last_update);
			gm_snprintf(tmpstr, sizeof(tmpstr), "Retry in %ds", MAX(0, when));
		}
		a = tmpstr;
		break;
	case GTA_DL_SINKING:
		gm_snprintf(tmpstr, sizeof(tmpstr), "Sinking (%u bytes left)",
			d->sinkleft);
		a = tmpstr;
		break;
	default:
		gm_snprintf(tmpstr, sizeof(tmpstr), "UNKNOWN STATUS %u",
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

	/*
	 * Prefix vendor name with a '*' if they are considered as potentially
	 * banning us and we activated anti-banning features.
	 *		--RAM, 05/07/2003
	 */

	(void) gm_snprintf(tmpstr, sizeof(tmpstr), "%s%s",
		(d->server->attrs & DLS_A_BANNING) ? "*" : "",
		download_vendor(d));

	row = gtk_clist_find_row_from_data(clist_downloads,	(gpointer) d);
	gtk_clist_set_text(clist_downloads, row, c_dl_server, tmpstr);
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
		if (d->flags & DL_F_SHRUNK_REPLY)		/* Chunk shrunk by server! */
			and_more = "-";
	} else
		len = d->range_end - d->skip;

	len += d->overlap_size;

	rw = gm_snprintf(tmpstr, sizeof(tmpstr), "%s%s",
		compact_size(len), and_more);

	if (d->skip)
		gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw, " @ %s",
			compact_size(d->skip));

	row = gtk_clist_find_row_from_data(clist_downloads,	(gpointer) d);
	gtk_clist_set_text(clist_downloads, row, c_dl_range, tmpstr);
}

void gui_update_download_abort_resume(void)
{
	struct download *d;
	GList *l;
    GtkCList *clist_downloads;
	gboolean do_abort  = FALSE;
    gboolean do_resume = FALSE;
    gboolean do_remove = FALSE;
    gboolean do_queue  = FALSE;
    gboolean abort_sha1 = FALSE;

    clist_downloads = GTK_CLIST(lookup_widget(main_window, "clist_downloads"));


	for (l = clist_downloads->selection; l; l = l->next) {
		d = (struct download *)
			gtk_clist_get_row_data(clist_downloads, GPOINTER_TO_INT(l->data));

        if (!d) {
			g_warning
				("gui_update_download_abort_resume(): row %d has NULL data\n",
				 GPOINTER_TO_INT(l->data));
			continue;
		}

		g_assert(d->status != GTA_DL_REMOVED);

		switch (d->status) {
		case GTA_DL_COMPLETED:
		case GTA_DL_VERIFY_WAIT:
		case GTA_DL_VERIFYING:
		case GTA_DL_VERIFIED:
			break;
		default:
			do_queue = TRUE;
			break;
		}

        if (d->file_info->sha1 != NULL)
            abort_sha1 = TRUE;

		switch (d->status) {
		case GTA_DL_QUEUED:
			g_warning("gui_update_download_abort_resume(): "
				"found queued download '%s' in active download list !",
				d->file_name);
			continue;
		case GTA_DL_CONNECTING:
		case GTA_DL_PUSH_SENT:
		case GTA_DL_FALLBACK:
		case GTA_DL_REQ_SENT:
		case GTA_DL_HEADERS:
		case GTA_DL_RECEIVING:
		case GTA_DL_ACTIVE_QUEUED:
			do_abort = TRUE;
			break;
		case GTA_DL_ERROR:
		case GTA_DL_ABORTED:
			do_resume = TRUE;
            /* only check if file exists if really necessary */
            if (!do_remove && download_file_exists(d))
                do_remove = TRUE;
			break;
		case GTA_DL_TIMEOUT_WAIT:
			do_abort = do_resume = TRUE;
			break;
        default: ;
        /* FIXME: Is this fallthrough alright or not? */
		}

		if (do_abort & do_resume & do_remove)
			break;
	}

	gtk_widget_set_sensitive
        (lookup_widget(main_window, "button_downloads_abort"), do_abort);
	gtk_widget_set_sensitive
        (lookup_widget(popup_downloads, "popup_downloads_abort"), do_abort);
    gtk_widget_set_sensitive
        (lookup_widget(popup_downloads, "popup_downloads_abort_named"),
		do_abort);
    gtk_widget_set_sensitive
        (lookup_widget(popup_downloads, "popup_downloads_abort_host"),
		do_abort);
    gtk_widget_set_sensitive(
        lookup_widget(popup_downloads, "popup_downloads_abort_sha1"), 
        abort_sha1);
	gtk_widget_set_sensitive
        (lookup_widget(main_window, "button_downloads_resume"), do_resume);
	gtk_widget_set_sensitive
        (lookup_widget(popup_downloads, "popup_downloads_resume"), do_resume);
    gtk_widget_set_sensitive
        (lookup_widget(popup_downloads, "popup_downloads_remove_file"),
		do_remove);
    gtk_widget_set_sensitive
        (lookup_widget(popup_downloads, "popup_downloads_queue"), do_queue);
}

void gui_update_queue_frozen(void)
{
    static gboolean msg_displayed = FALSE;
    static statusbar_msgid_t id = {0, 0};

    GtkWidget *togglebutton_queue_freeze;

    togglebutton_queue_freeze =
        lookup_widget(main_window, "togglebutton_queue_freeze");

    if (gui_debug >= 3)
	printf("frozen %i, msg %i\n", download_queue_is_frozen(),
	    msg_displayed);

    if (download_queue_is_frozen() > 0) {
#ifndef USE_GTK2
    	gtk_widget_hide(lookup_widget(main_window, "vbox_queue_freeze"));
    	gtk_widget_show(lookup_widget(main_window, "vbox_queue_thaw"));
#endif
    	/*
		gtk_label_set_text(
            GTK_LABEL(GTK_BIN(togglebutton_queue_freeze)->child),
			"Thaw queue");
		*/
        if (!msg_displayed) {
            msg_displayed = TRUE;
          	id = statusbar_gui_message(0, "QUEUE FROZEN");
        }
    } else {
#ifndef USE_GTK2
    	gtk_widget_show(lookup_widget(main_window, "vbox_queue_freeze"));
    	gtk_widget_hide(lookup_widget(main_window, "vbox_queue_thaw"));
#endif
    	/*
		gtk_label_set_text(
            GTK_LABEL(GTK_BIN(togglebutton_queue_freeze)->child),
			"Freeze queue");
		*/
        if (msg_displayed) {
            msg_displayed = FALSE;
            statusbar_gui_remove(id);
        }
	} 

    gtk_signal_handler_block_by_func(
        GTK_OBJECT(togglebutton_queue_freeze),
        GTK_SIGNAL_FUNC(on_togglebutton_queue_freeze_toggled),
        NULL);

    gtk_toggle_button_set_active(
        GTK_TOGGLE_BUTTON(togglebutton_queue_freeze),
        download_queue_is_frozen() > 0);
    
    gtk_signal_handler_unblock_by_func(
        GTK_OBJECT(togglebutton_queue_freeze),
        GTK_SIGNAL_FUNC(on_togglebutton_queue_freeze_toggled),
        NULL);
}

/* Add a download to the GUI */

void download_gui_add(struct download *d)
{
	gchar *titles[6];
	gint row;
	GdkColor *color;
	GtkCList* clist_downloads;
	static gchar vendor[256];

	g_return_if_fail(d);

	if (DOWNLOAD_IS_VISIBLE(d)) {
		g_warning
			("download_gui_add() called on already visible download '%s' !",
			 d->file_name);
		return;
	}

	clist_downloads = GTK_CLIST
		(lookup_widget(main_window, "clist_downloads"));

	color = &(gtk_widget_get_style(GTK_WIDGET(clist_downloads))
				->fg[GTK_STATE_INSENSITIVE]);

	/*
	 * When `record_index' is URN_INDEX, the `file_name' is the URN, which
	 * is not something really readable.  Better display the target filename
	 * on disk in that case.
	 *		--RAM, 22/10/2002
	 */

	gm_snprintf(vendor, sizeof(vendor), "%s%s",
		(d->server->attrs & DLS_A_BANNING) ? "*" : "",
		download_vendor_str(d));

	if (DOWNLOAD_IS_QUEUED(d)) {		/* This is a queued download */
		GtkCList* clist_downloads_queue;

        titles[c_queue_filename] = d->record_index == URN_INDEX ?
			d->file_info->file_name : d->file_name;
        titles[c_queue_server] = vendor;
        titles[c_queue_status] = "";
		titles[c_queue_size] = short_size(d->file_info->size);
        titles[c_queue_host] = is_faked_download(d) ? "" :
			ip_port_to_gchar(download_ip(d), download_port(d));

		clist_downloads_queue = GTK_CLIST
			(lookup_widget(main_window, "clist_downloads_queue"));

		row = gtk_clist_append(clist_downloads_queue, titles);
		gtk_clist_set_row_data(clist_downloads_queue, row, (gpointer) d);
		if (d->always_push)
			 gtk_clist_set_foreground(clist_downloads_queue, row, color);
	} else {					/* This is an active download */

		titles[c_dl_filename] = d->record_index == URN_INDEX ?
			d->file_info->file_name : d->file_name;
		titles[c_dl_server] = vendor;
		titles[c_dl_status] = "";
		titles[c_dl_size] = short_size(d->file_info->size);
		titles[c_dl_range] = "";
		titles[c_dl_host] = is_faked_download(d) ? "" :
			ip_port_to_gchar(download_ip(d), download_port(d));

		row = gtk_clist_append(clist_downloads, titles);
		gtk_clist_set_row_data(clist_downloads, row, (gpointer) d);
		if (DOWNLOAD_IS_IN_PUSH_MODE(d))
			 gtk_clist_set_foreground(clist_downloads, row, color);
	}

	d->visible = TRUE;
}

/*
 * download_gui_remove:
 *
 * Remove a download from the GUI.
 */
void download_gui_remove(struct download *d)
{
	gint row;

	g_return_if_fail(d);

	if (!DOWNLOAD_IS_VISIBLE(d)) {
		g_warning
			("download_gui_remove() called on invisible download '%s' !",
			 d->file_name);
		return;
	}

	if (DOWNLOAD_IS_QUEUED(d)) {
		GtkCList *clist_downloads_queue;

		clist_downloads_queue = GTK_CLIST
			(lookup_widget(main_window, "clist_downloads_queue"));

		row =
			gtk_clist_find_row_from_data(clist_downloads_queue, (gpointer) d);
		if (row != -1)
			gtk_clist_remove(clist_downloads_queue, row);
		else
			g_warning("download_gui_remove(): "
				"Queued download '%s' not found in clist !?", d->file_name);
	} else {
		GtkCList *clist_downloads;

		clist_downloads = GTK_CLIST
			(lookup_widget(main_window, "clist_downloads"));

		row = gtk_clist_find_row_from_data(clist_downloads, (gpointer) d);
		if (row != -1)
			gtk_clist_remove(clist_downloads, row);
		else
			g_warning("download_gui_remove(): "
				"Active download '%s' not found in clist !?", d->file_name);
	}

	d->visible = FALSE;

	gui_update_download_abort_resume();
	gui_update_download_clear();
}
