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

#include "gui.h"

RCSID("$Id$")

#include "gtk/downloads.h"
#include "gtk/downloads_common.h"
#include "gtk/gtk-missing.h"
#include "gtk/gtkcolumnchooser.h"
#include "gtk/search_common.h"
#include "gtk/settings.h"
#include "gtk/statusbar.h"

#ifdef USE_GTK2
#include "gtk2/downloads_cb.h"
#endif
#ifdef USE_GTK1
#include "gtk1/downloads_cb.h"
#endif

#include "if/bridge/ui2c.h"
#include "if/core/bsched.h"
#include "if/core/http.h"
#include "if/core/http.h"
#include "if/core/pproxy.h"
#include "if/core/sockets.h"
#include "if/gui_property_priv.h"

#include "lib/atoms.h"
#include "lib/glib-missing.h"
#include "lib/utf8.h"

#include "lib/override.h"	/* Must be the last header included */

#define IO_STALLED		60	/**< If nothing exchanged after that many secs */
#define IO_AVG_RATE		5	/**< Compute global recv rate every 5 secs */

static gboolean update_download_clear_needed = FALSE;

/**
 * Remember that we need to check for cleared downloads at the next
 * invocation of gui_update_download_clear_now(), which happens once
 * every second only to avoid too frequent costly list traversals.
 */
void
gui_update_download_clear(void)
{
	update_download_clear_needed = TRUE;
}

/**
 *	Checks if there are any active downloads that are clearable
 *  If so, this activates the "Clear Stopped" button
 */
void
gui_update_download_clear_now(void)
{
	if (!update_download_clear_needed)
		return;

	gtk_widget_set_sensitive(
        gui_main_window_lookup("button_downloads_clear_stopped"),
        guc_download_something_to_clear());
}

/**
 * Enable the "start now" menu entry for queued items.
 */
void
gui_download_enable_start_now(guint32 running_downloads, guint32 max_downloads)
{
	(void) running_downloads;
	(void) max_downloads;
}


/**
 *	Clear all stopped, complete, and unavailable downloads.
 */
void
on_button_downloads_clear_stopped_clicked(GtkButton *unused_button,
	gpointer unused_udata)
{
	(void) unused_button;
	(void) unused_udata;
	guc_download_clear_stopped(TRUE, TRUE, TRUE, TRUE, TRUE);
}


/**
 *	Freeze the downloads queue.
 */
void
on_togglebutton_queue_freeze_toggled(GtkToggleButton *togglebutton,
	gpointer unused_udata)
{
	(void) unused_udata;

    if (gtk_toggle_button_get_active(togglebutton)) {
        guc_download_freeze_queue();
    } else {
        guc_download_thaw_queue();
    }
}

const gchar *
download_progress_to_string(const struct download *d)
{
	static gchar buf[32];

	gm_snprintf(buf, sizeof buf, "%5.2f%%",
		100.0 * guc_download_total_progress(d));
	return buf;
}

const gchar *
source_progress_to_string(const struct download *d)
{
	static gchar buf[32];

	switch (d->status) {
	case GTA_DL_RECEIVING:
	case GTA_DL_IGNORING:
		gm_snprintf(buf, sizeof buf, "%5.2f%%",
			100.0 * guc_download_source_progress(d));
		break;
	default:
		buf[0] = '\0';
	}
	return buf;
}

void
downloads_gui_set_details(const gchar *filename, filesize_t filesize,
	const struct sha1 *sha1, const struct tth *tth)
{
	downloads_gui_clear_details();

	downloads_gui_append_detail(_("Filename"),
		lazy_filename_to_ui_string(filename));
	downloads_gui_append_detail(_("Size"),
		nice_size(filesize, show_metric_units()));
	downloads_gui_append_detail(_("SHA-1"),
		sha1 ? sha1_to_urn_string(sha1) : NULL);
	downloads_gui_append_detail(_("Bitprint"),
		sha1 && tth ? bitprint_to_urn_string(sha1, tth) : NULL);
}

const gchar *
downloads_gui_status_string(const struct download *d)
{
	static gchar tmpstr[4096];
	const gchar *status = NULL;
	time_t now = tm_time();
	const fileinfo_t *fi;
	gint rw;

	download_check(d);
	fi = d->file_info;
	file_info_check(fi);
		
	switch (d->status) {
	case GTA_DL_ACTIVE_QUEUED:	/* JA, 31 jan 2003 Active queueing */
		{
			time_delta_t elapsed = delta_time(now, d->last_update);

			elapsed = delta_time(now, d->last_update);
			elapsed = MAX(0, elapsed);
			elapsed = MIN(elapsed, INT_MAX);
			
			rw = gm_snprintf(tmpstr, sizeof(tmpstr), "%s", _("Queued"));

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
			rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
				" <PFS %4.02f%%>", d->ranges_size * 100.0 / fi->size);
		}

		status = tmpstr;
		break;
	case GTA_DL_QUEUED:
		if (FILE_INFO_COMPLETE(d->file_info)) {
			rw = gm_snprintf(tmpstr, sizeof tmpstr, _("Complete"));
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
			rw = gm_snprintf(tmpstr, sizeof(tmpstr),
					_("Sending request (%u%%)"),
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
			time_delta_t t = delta_time(d->last_update, d->start_date);
			
			rw = gm_snprintf(tmpstr, sizeof(tmpstr), "%s (%s) %s",
				FILE_INFO_COMPLETE(fi) ? _("Completed") : _("Chunk done"),
				short_rate((d->range_end - d->skip + d->overlap_size) / t,
					show_metric_units()),
				short_time(t));
		} else {
			rw = gm_snprintf(tmpstr, sizeof(tmpstr), "%s (< 1s)",
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
			const gchar *sha1_status;
			
			if (fi->cha1) {
				if (fi->sha1) {
					sha1_status = sha1_eq(fi->sha1, fi->cha1)
						? _("SHA-1 OK")
						: _("SHA-1 MISMATCH");
				} else {
					sha1_status = _("SHA-1 calculated");
				}
			} else {
				sha1_status = _("SHA-1 VERIFICATION FAILED");
			}
			rw = gm_snprintf(tmpstr, sizeof tmpstr, "%s", sha1_status);

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
				rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
						"%s", _("; Waiting for moving..."));
				break;
			case GTA_DL_MOVING:
				rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					_("; Moving (%.02f%%)"),
					((gdouble) fi->copied / fi->size) * 100.0);
				break;
			case GTA_DL_DONE:
				if (fi->copy_elapsed) {
					rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
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
	case GTA_DL_IGNORING:
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
				rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					" <PFS %4.02f%%>", d->ranges_size * 100.0 / fi->size);

			/*
			 * If more than one request served with the same connection,
			 * show them how many were served (adding 1 for current request).
			 */

			if (d->served_reqs)
				rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					" #%u", d->served_reqs + 1);

			if (GTA_DL_IGNORING == d->status)
				rw += gm_snprintf(&tmpstr[rw], sizeof(tmpstr)-rw,
					" (%s)", _("ignoring"));

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
			time_delta_t elapsed;
			unsigned when;
			
			elapsed = delta_time(now, d->last_update);
			if (elapsed < (time_delta_t) d->timeout_delay) {
				elapsed = MAX(0, elapsed);
				when = d->timeout_delay - elapsed; 
			} else {
				when = 0;
			}
			rw = gm_snprintf(tmpstr, sizeof tmpstr, _("Retry in %us"), when);
		}
		status = tmpstr;
		break;
	case GTA_DL_SINKING:
		{
			gchar buf[UINT64_DEC_BUFLEN];
			
			uint64_to_string_buf(d->sinkleft, buf, sizeof buf);
			rw = gm_snprintf(tmpstr, sizeof tmpstr,
				_("Sinking (%s bytes left)"), buf);
		}
		status = tmpstr;
		break;
	default:
		rw = gm_snprintf(tmpstr, sizeof tmpstr, "UNKNOWN STATUS %u", d->status);
		status = tmpstr;
	}

	return status;
}

const gchar *
downloads_gui_range_string(const struct download *d)
{
	static char buf[256];
	char range_start[64];
	const char *and_more = "";
	filesize_t length;
	gboolean metric;

	download_check(d);

	if (d->file_info->use_swarming) {
		length = d->size;
		if (d->range_end > d->skip + d->size)
			and_more = "+";
		if (d->flags & DL_F_SHRUNK_REPLY)		/* Chunk shrunk by server! */
			and_more = "-";
	} else {
		length = d->range_end - d->skip;
	}
	length += d->overlap_size;

	metric = show_metric_units();
	if (d->skip) {
		g_strlcpy(range_start, compact_size(d->skip, metric),
			sizeof range_start);
	} else {
		range_start[0] = '\0';
	}

	concat_strings(buf, sizeof buf,
		compact_size(length, metric), and_more,
		range_start[0] ? " @ " : "", range_start,
		(void *)0);
	return buf;
}

static void
update_popup_downloads_start_now(void)
{
	gboolean sensitive = TRUE;

	switch (fi_gui_get_current_page()) {
	case nb_downloads_page_active:
	case nb_downloads_page_finished:
	case nb_downloads_page_seeding:
		sensitive = FALSE;
		break;
	case nb_downloads_page_queued:
	case nb_downloads_page_paused:
	case nb_downloads_page_incomplete:
	case nb_downloads_page_all:
		sensitive = TRUE;
		break;
	case nb_downloads_page_num:
		g_assert_not_reached();
		break;
	}
	widget_set_visible(gui_popup_downloads_lookup("popup_downloads_start_now"),
		sensitive);
}

static void
update_popup_downloads_queue(void)
{
	gboolean sensitive = TRUE;

	switch (fi_gui_get_current_page()) {
	case nb_downloads_page_active:
	case nb_downloads_page_paused:
	case nb_downloads_page_incomplete:
	case nb_downloads_page_all:
		sensitive = TRUE;
		break;
	case nb_downloads_page_queued:
	case nb_downloads_page_finished:
	case nb_downloads_page_seeding:
		sensitive = FALSE;
		break;
	case nb_downloads_page_num:
		g_assert_not_reached();
		break;
	}
	widget_set_visible(gui_popup_downloads_lookup("popup_downloads_queue"),
		sensitive);
}

static void
update_popup_downloads_resume(void)
{
	gboolean sensitive = TRUE;

	switch (fi_gui_get_current_page()) {
	case nb_downloads_page_queued:
	case nb_downloads_page_paused:
	case nb_downloads_page_incomplete:
	case nb_downloads_page_all:
		sensitive = TRUE;
		break;
	case nb_downloads_page_active:
	case nb_downloads_page_finished:
	case nb_downloads_page_seeding:
		sensitive = FALSE;
		break;
	case nb_downloads_page_num:
		g_assert_not_reached();
		break;
	}
	widget_set_visible(gui_popup_downloads_lookup("popup_downloads_resume"),
		sensitive);
}

static void
update_popup_downloads_pause(void)
{
	gboolean sensitive = TRUE;

	switch (fi_gui_get_current_page()) {
	case nb_downloads_page_active:
	case nb_downloads_page_queued:
	case nb_downloads_page_incomplete:
	case nb_downloads_page_all:
		sensitive = TRUE;
		break;
	case nb_downloads_page_paused:
	case nb_downloads_page_finished:
	case nb_downloads_page_seeding:
		sensitive = FALSE;
		break;
	case nb_downloads_page_num:
		g_assert_not_reached();
		break;
	}
	widget_set_visible(gui_popup_downloads_lookup("popup_downloads_pause"),
		sensitive);
}

void
downloads_gui_update_popup_downloads(void)
{
	update_popup_downloads_start_now();
	update_popup_downloads_queue();
	update_popup_downloads_resume();
	update_popup_downloads_pause();
}

/***
 *** Popup menu: downloads
 ***/

static void
push_activate(void)
{
	GSList *sl, *selected;
	gboolean send_pushes, firewalled;

   	gnet_prop_get_boolean_val(PROP_SEND_PUSHES, &send_pushes);
   	gnet_prop_get_boolean_val(PROP_IS_FIREWALLED, &firewalled);

   	if (firewalled || !send_pushes)
       	return;

	selected = fi_gui_sources_select(TRUE);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		guc_download_fallback_to_push(d, FALSE, TRUE);
	}
	g_slist_free(selected);
}


/**
 * Causes all selected active downloads to fall back to push.
 */
void
on_popup_sources_push_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	push_activate();
}

/**
 * Initiates a browse host request to the currently selected host.
 */
void
on_popup_sources_browse_host_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = fi_gui_sources_select(TRUE);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		const struct download *d = sl->data;
   		search_gui_new_browse_host(
			download_hostname(d), download_addr(d), download_port(d),
			download_guid(d), NULL, 0);
	}
	g_slist_free(selected);
}

/**
 * For all selected active downloads, remove all downloads with
 * the same host.
 */
void
on_popup_sources_forget_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;
    guint removed = 0;

	(void) unused_menuitem;
	(void) unused_udata;

	selected = fi_gui_sources_select(TRUE);
	if (!selected)
		return;

   	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		removed += guc_download_remove_all_from_peer(download_guid(d),
						download_addr(d), download_port(d), FALSE);
	}
	g_slist_free(selected);

    statusbar_gui_message(15,
		NG_("Forgot %u download", "Forgot %u downloads", removed),
		removed);
}

static void
copy_selection_to_clipboard(void)
{
#if GTK_CHECK_VERSION(2,0,0)
	GSList *selected;

   	selected = fi_gui_sources_select(TRUE);
	if (selected) {
		struct download *d = selected->data;
		gchar *url;

		gtk_clipboard_clear(gtk_clipboard_get(GDK_SELECTION_PRIMARY));
		gtk_clipboard_clear(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD));

       	url = guc_download_build_url(d);
		if (url) {
			gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_PRIMARY),
					url, -1);
			gtk_clipboard_set_text(gtk_clipboard_get(GDK_SELECTION_CLIPBOARD),
					url, -1);
		}
		G_FREE_NULL(url);
	}
	g_slist_free(selected);
#else	/* Gtk+ 1.2 */
	/* FIXME: Implement */
#endif	/* Gtk+ 2.x*/
}

/**
 * For selected download, copy URL to clipboard.
 */
void
on_popup_sources_copy_url_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	copy_selection_to_clipboard();
}


/**
 * For all selected active downloads connect to host.
 */
void
on_popup_sources_connect_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = fi_gui_sources_select(TRUE);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		const struct download *d = sl->data;
   		guc_node_add(download_addr(d), download_port(d), SOCK_F_FORCE);
   	}
	g_slist_free(selected);
}

/**
 * For all selected downloads, activate them.
 */
void
on_popup_downloads_start_now_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = fi_gui_sources_of_selected_files(TRUE);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		guc_download_start(d, TRUE);
   	}
	g_slist_free(selected);
}

/**
 * For all selected downloads, activate them.
 */
void
on_popup_sources_start_now_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = fi_gui_sources_select(TRUE);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		guc_download_start(d, TRUE);
   	}
	g_slist_free(selected);
}

/**
 * For all selected downloads, activate them.
 */
void
on_popup_downloads_pause_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = fi_gui_sources_of_selected_files(TRUE);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		guc_download_pause(d);
   	}
	g_slist_free(selected);
}

/**
 * For all selected downloads, activate them.
 */
void
on_popup_sources_pause_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = fi_gui_sources_select(TRUE);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		guc_download_pause(d);
   	}
	g_slist_free(selected);
}

/**
 * For all selected downloads, resume them.
 */
void
on_popup_downloads_resume_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = fi_gui_sources_of_selected_files(TRUE);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		guc_download_resume(d);
   	}
	g_slist_free(selected);
}

/**
 * For all selected downloads, resume them.
 */
void
on_popup_sources_resume_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = fi_gui_sources_select(TRUE);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		guc_download_resume(d);
   	}
	g_slist_free(selected);
}

/**
 * For all selected downloads, queue them.
 */
void
on_popup_downloads_queue_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = fi_gui_sources_of_selected_files(TRUE);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		guc_download_requeue(d);
   	}
	g_slist_free(selected);
}

/**
 * For all selected downloads, queue them.
 */
void
on_popup_sources_queue_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	GSList *sl, *selected;

	(void) unused_menuitem;
	(void) unused_udata;

   	selected = fi_gui_sources_select(TRUE);
	if (!selected)
		return;

	for (sl = selected; sl; sl = g_slist_next(sl)) {
		struct download *d = sl->data;
		guc_download_requeue(d);
   	}
	g_slist_free(selected);
}

/**
 * For all selected downloads, queue them.
 */
void
on_popup_downloads_abort_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	fi_gui_purge_selected_files();
}

/***
 *** downloads pane
 ***/


void
on_popup_downloads_config_cols_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	fi_gui_files_configure_columns();
}

void
on_popup_sources_config_cols_activate(GtkMenuItem *unused_menuitem,
	gpointer unused_udata)
{
    GtkWidget *widget, *cc;

	(void) unused_menuitem;
	(void) unused_udata;

#if GTK_CHECK_VERSION(2,0,0)
	widget = gui_main_window_lookup("treeview_download_sources");
#else
	widget = gui_main_window_lookup("clist_download_sources");
#endif

    cc = gtk_column_chooser_new(GTK_WIDGET(widget));
    gtk_menu_popup(GTK_MENU(cc), NULL, NULL, NULL, NULL, 1,
		gtk_get_current_event_time());
}

/***
 *** Queued downloads
 ***/


/**
 * Select all downloads that match given regex in editable.
 */
void
on_entry_downloads_regex_activate(GtkEditable *editable, gpointer unused_udata)
{
    gchar *regex;

	(void) unused_udata;

    regex = STRTRACK(gtk_editable_get_chars(GTK_EDITABLE(editable), 0, -1));
	g_return_if_fail(regex != NULL);

	fi_gui_select_by_regex(regex);
	G_FREE_NULL(regex);
}


/**
 * When the right mouse button is clicked on the active downloads
 * treeview, show the popup with the context menu.
 */
gboolean
on_download_files_button_press_event(GtkWidget *unused_widget,
	GdkEventButton *event, gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_udata;

	if (
		3 == event->button &&
		0 == (gtk_accelerator_get_default_mod_mask() & event->state)
	) {
    	gtk_menu_popup(GTK_MENU(gui_popup_downloads()), NULL, NULL, NULL, NULL,
        	event->button, event->time);
		return TRUE;
	}
	return FALSE;
}

/**
 * When the right mouse button is clicked on the active downloads
 * treeview, show the popup with the context menu.
 */
gboolean
on_download_sources_button_press_event(GtkWidget *unused_widget,
	GdkEventButton *event, gpointer unused_udata)
{
	(void) unused_widget;
	(void) unused_udata;

	if (
		3 == event->button &&
		0 == (gtk_accelerator_get_default_mod_mask() & event->state)
	) {
    	gtk_menu_popup(GTK_MENU(gui_popup_sources()), NULL, NULL, NULL, NULL,
        	event->button, event->time);
		return TRUE;
	}
	return FALSE;
}

/* vi: set ts=4 sw=4 cindent: *//* vi: set ts=4 sw=4 cindent: */
