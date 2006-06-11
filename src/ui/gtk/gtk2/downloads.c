/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi, Richard Eckart
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

#include "gtk/gui.h"

RCSID("$Id$");

#if !GTK_CHECK_VERSION(2,5,0)
#include "pbarcellrenderer.h"
#endif

#include "downloads_cb.h"

#include "gtk/downloads.h"
#include "gtk/downloads_common.h"
#include "gtk/statusbar.h"
#include "gtk/columns.h"
#include "gtk/notebooks.h"
#include "gtk/gtk-missing.h"
#include "gtk/misc.h"
#include "gtk/settings.h"

#include "if/core/bsched.h"
#include "if/core/downloads.h"
#include "if/core/http.h"
#include "if/core/pproxy.h"
#include "if/gui_property.h"
#include "if/bridge/ui2c.h"

#include "lib/atoms.h"
#include "lib/glib-missing.h"
#include "lib/utf8.h"
#include "lib/tm.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

void fi_gui_add_download(struct download *d);
void fi_gui_remove_download(struct download *d);
void fi_gui_download_set_status(struct download *d, const gchar *s);

/***
 *** Private
 ***/
 
/***
 *** Public interface
 ***/
 
/**
 *	Initalize the download gui.
 */
void
downloads_gui_init(void)
{
}

/**
 * Shutdown procedures.
 */
void
downloads_gui_shutdown(void)
{
}

/**
 *	Add a download to either the active or queued download treeview depending
 *	on the download's flags.  This function handles grouping new downloads
 * 	appropriately and creation of parent/child nodes.
 */
void
download_gui_add(download_t *d)
{
	download_check(d);
	
	fi_gui_add_download(d);
	d->visible = TRUE;
}


/**
 *	Remove a download from the GUI.
 */
void
download_gui_remove(download_t *d)
{
	download_check(d);
	
	fi_gui_remove_download(d);
	d->visible = FALSE;
}

/**
 *	Update the gui to reflect the current state of the given download
 */
void
gui_update_download(download_t *d, gboolean force)
{
	static gchar tmpstr[4096];
	const gchar *status = NULL;
	time_t now = tm_time();
	const fileinfo_t *fi;
	gint rw;

	download_check(d);
	(void) force;

    if (d->last_gui_update == now && !force)
		return;

	d->last_gui_update = now;
	fi = d->file_info;

	switch (d->status) {
	case GTA_DL_ACTIVE_QUEUED:	/* JA, 31 jan 2003 Active queueing */
		{
			gint elapsed = delta_time(now, d->last_update);

			rw = gm_snprintf(tmpstr, sizeof(tmpstr), _("Queued"));

			if (guc_get_parq_dl_position(d) > 0) {

				rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					_(" (slot %u"),		/* ) */
					guc_get_parq_dl_position(d));

				if (guc_get_parq_dl_queue_length(d) > 0) {
					rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
						"/%u", (guint) guc_get_parq_dl_queue_length(d));
				}

				if (guc_get_parq_dl_eta(d)  > 0) {
					rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
						_(", ETA: %s"),
						short_time((guc_get_parq_dl_eta(d)
							- elapsed)));
				}

				rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw, /* ( */ ")");
			}

			rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					_(" retry in %us"),
					(guint) (guc_get_parq_dl_retry_delay(d) - elapsed));
		}

		/*
		 * If source is a partial source, show it.
		 */

		if (d->ranges != NULL) {
			gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
				" <PFS %4.02f%%>", d->ranges_size * 100.0 / fi->size);
		}

		status = tmpstr;
		break;
	case GTA_DL_QUEUED:
		if (FILE_INFO_COMPLETE(d->file_info)) {
			gm_snprintf(tmpstr, sizeof tmpstr, _("Complete"));
			status = tmpstr;
		} else {
			status = d->remove_msg ? d->remove_msg : "";
		}
		break;

	case GTA_DL_CONNECTING:
		status = _("Connecting...");
		break;

	case GTA_DL_PUSH_SENT:
	case GTA_DL_FALLBACK:
		{
			if (d->cproxy != NULL) {
				const struct cproxy *cp = d->cproxy;

				if (cp->done) {
					if (cp->sent)
						rw = gm_snprintf(tmpstr, sizeof(tmpstr),
								cp->directly
									? _("Push sent directly")
									: _("Push sent"));
					else
						rw = gm_snprintf(tmpstr, sizeof(tmpstr),
								_("Failed to send push"));
				} else
					rw = gm_snprintf(tmpstr, sizeof(tmpstr),
							_("Sending push"));

				rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw, _(" via %s"),
						host_addr_port_to_string(cproxy_addr(cp),
							cproxy_port(cp)));

				if (!cp->done) {
					switch (cp->state) {
					case HTTP_AS_CONNECTING:
						status = _("Connecting");
						break;
					case HTTP_AS_REQ_SENDING:
						status = _("Sending request");
						break;
					case HTTP_AS_REQ_SENT:
						status = _("Request sent");
						break;
					case HTTP_AS_HEADERS:
						status = _("Reading headers");
						break;
					default:
						status = "...";
						break;
					}

					rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
							": %s", status);
				}

				status = tmpstr;
			} else {
				switch (d->status) {
				case GTA_DL_PUSH_SENT:
					status = _("Push sent");
					break;
				case GTA_DL_FALLBACK:
					status = _("Falling back to push");
					break;
				default:
					break;
				}
			}
		}
		break;

	case GTA_DL_REQ_SENDING:
		if (d->req != NULL) {
			gm_snprintf(tmpstr, sizeof(tmpstr), _("Sending request (%u%%)"),
				(guint) guc_download_get_http_req_percent(d));
			status = tmpstr;
		} else
			status = _("Sending request");
		break;

	case GTA_DL_REQ_SENT:
		status = _("Request sent");
		break;

	case GTA_DL_HEADERS:
		status = _("Receiving headers");
		break;

	case GTA_DL_ABORTED:
		status = d->unavailable ? _("Aborted (Server down)") : _("Aborted");
		break;

	case GTA_DL_COMPLETED:
		if (d->last_update != d->start_date) {
			guint32 t = delta_time(d->last_update, d->start_date);
			
			gm_snprintf(tmpstr, sizeof(tmpstr), "%s (%s) %s",
				FILE_INFO_COMPLETE(fi) ? _("Completed") : _("Chunk done"),
				short_rate((d->range_end - d->skip + d->overlap_size) / t,
					show_metric_units()),
				short_time(t));
		} else {
			gm_snprintf(tmpstr, sizeof(tmpstr), "%s (< 1s)",
				FILE_INFO_COMPLETE(fi) ? _("Completed") : _("Chunk done"));
		}
		status = tmpstr;
		break;

	case GTA_DL_VERIFY_WAIT:
		g_assert(FILE_INFO_COMPLETE(fi));
		g_strlcpy(tmpstr, _("Waiting for SHA1 checking..."), sizeof(tmpstr));
		status = tmpstr;
		break;

	case GTA_DL_VERIFYING:
		g_assert(FILE_INFO_COMPLETE(fi));
		gm_snprintf(tmpstr, sizeof(tmpstr),
			_("Computing SHA1 (%.02f%%)"), fi->cha1_hashed * 100.0 / fi->size);
		status = tmpstr;
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
				guint elapsed = fi->cha1_elapsed;
			
				rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					" (%s) %s",
					short_rate(fi->cha1_hashed / (elapsed ? elapsed : 1),
						show_metric_units()),
					short_time(fi->cha1_elapsed));
			}

			switch (d->status) {
			case GTA_DL_MOVE_WAIT:
				g_strlcpy(&tmpstr[rw], _("; Waiting for moving..."),
					sizeof(tmpstr)-rw);
				break;
			case GTA_DL_MOVING:
				gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					_("; Moving (%.02f%%)"),
					((gdouble) fi->copied / fi->size) * 100.0);
				break;
			case GTA_DL_DONE:
				if (fi->copy_elapsed) {
					gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
						_("; Moved (%s) %s"),
						short_rate(fi->copied / fi->copy_elapsed,
							show_metric_units()),
						short_time(fi->copy_elapsed));
				}
				break;
			default:
				break;
			}
		}
		status = tmpstr;
		break;

	case GTA_DL_RECEIVING:
		if (d->pos + download_buffered(d) > d->skip) {
			gint bps;
			guint32 avg_bps;
			filesize_t downloaded;
			gboolean stalled;

			downloaded = d->pos - d->skip + download_buffered(d);
			if (d->bio) {
				bps = bio_bps(d->bio);
				avg_bps = bio_avg_bps(d->bio);
			} else {
				bps = 0;
				avg_bps = 0;
			}

			if (avg_bps <= 10 && d->last_update != d->start_date) {
				avg_bps = downloaded / delta_time(d->last_update,
											d->start_date);
			}

			stalled = delta_time(now, d->last_update) > IO_STALLED;
			rw = 0;

			if (!bps) {
				bps = avg_bps;
			}
			if (bps && !stalled) {
				filesize_t remain;
				guint32 s;

                if (d->size > downloaded) {
                    remain = d->size - downloaded;
				} else {
					remain = 0;
				}
                s = remain / bps;
				rw += gm_snprintf(&tmpstr[rw], sizeof tmpstr - rw,
						"(%s) TR: %s",
						short_rate(bps, show_metric_units()),
						short_time(s));
			} else {
				rw += gm_snprintf(tmpstr, sizeof tmpstr - rw, "%s",
						stalled	? _("(stalled)") : _("Connected"));
			}

			/*
			 * If source is a partial source, show it.
			 */

			if (d->ranges != NULL)
				gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					" <PFS %4.02f%%>", d->ranges_size * 100.0 / fi->size);

			/*
			 * If more than one request served with the same connection,
			 * show them how many were served (adding 1 for current request).
			 */

			if (d->served_reqs)
				gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					" #%u", d->served_reqs + 1);

			status = tmpstr;
		} else {
			status = _("Connected");
		}
		break;

	case GTA_DL_ERROR:
		status = d->remove_msg ? d->remove_msg : _("Unknown error");
		break;

	case GTA_DL_TIMEOUT_WAIT:
		{
			guint when = d->timeout_delay - delta_time(now, d->last_update);
			gm_snprintf(tmpstr, sizeof(tmpstr), _("Retry in %us"), when);
		}
		status = tmpstr;
		break;
	case GTA_DL_SINKING:
		{
			gchar buf[UINT64_DEC_BUFLEN];
			
			uint64_to_string_buf(d->sinkleft, buf, sizeof buf);
			gm_snprintf(tmpstr, sizeof tmpstr,
				_("Sinking (%s bytes left)"), buf);
		}
		status = tmpstr;
		break;
	default:
		gm_snprintf(tmpstr, sizeof tmpstr, "UNKNOWN STATUS %u", d->status);
		status = tmpstr;
	}

    if (d->status == GTA_DL_QUEUED) {
		/* Download is done */
	}
	fi_gui_download_set_status(d, status);
}

/**
 *	Determines if abort/resume buttons should be sensitive or not
 *  Determines if the queue and abort options should be available in the
 *	treeview popups.
 */
void
gui_update_download_abort_resume(void)
{
}


/**
 *	Expand all nodes in given tree, either downloads or downloads_queue
 */
void
downloads_gui_expand_all(void)
{
	gtk_tree_view_expand_all(
		GTK_TREE_VIEW(lookup_widget(main_window, "treeview_downloads")));
}


/**
 *	Collapse all nodes in given, tree either downloads or downloads_queue
 */
void
downloads_gui_collapse_all(void)
{
	gtk_tree_view_collapse_all(
		GTK_TREE_VIEW(lookup_widget(main_window, "treeview_downloads")));
}

/**
 * Periodically called to update downloads display.
 */
void
downloads_gui_update_display(time_t unused_now)
{
	(void) unused_now;

	/* Nothing needed for GTK2 */
}

/* vi: set ts=4 sw=4 cindent: */
