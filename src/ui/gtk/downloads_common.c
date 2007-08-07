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
#include "gtk/misc.h"
#include "gtk/search_common.h"
#include "gtk/settings.h"
#include "gtk/statusbar.h"
#include "gtk/visual_progress.h"

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
#include "lib/walloc.h"

#include "lib/override.h"	/* Must be the last header included */

#define IO_STALLED		60	/**< If nothing exchanged after that many secs */

struct fileinfo_data {
	const char *filename;	/* atom */
	char *status;			/* g_strdup */
	hash_list_t *downloads;

	void *user_data;

	filesize_t size;
	filesize_t done;
	filesize_t uploaded;

	gnet_fi_t handle;

	unsigned actively_queued;
	unsigned passively_queued;
	unsigned life_count;
	unsigned recv_count;
	unsigned recv_rate;

	unsigned paused:1;
	unsigned hashed:1;
	unsigned seeding:1;

	unsigned matched:1;

	guint16 progress; /* 0..1000 (per mille) */
};

static gnet_fi_t last_shown;
static gboolean  last_shown_valid;

static GHashTable *fi_handles;	/* gnet_fi_t -> row */
static GHashTable *fi_updates;	/* gnet_fi_t */

static enum nb_downloads_page current_page;

static gboolean update_download_clear_needed = FALSE;

static regex_t *filter_regex;

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
 *	Clear all stopped, complete, and unavailable downloads.
 */
void
on_button_downloads_clear_stopped_clicked(GtkButton *unused_button,
	void *unused_udata)
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
	void *unused_udata)
{
	(void) unused_udata;

    if (gtk_toggle_button_get_active(togglebutton)) {
        guc_download_freeze_queue();
    } else {
        guc_download_thaw_queue();
    }
}

static const char *
source_progress_to_string(const struct download *d)
{
	static char buf[32];

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

static void
fi_gui_set_details(const char *filename, filesize_t filesize,
	const struct sha1 *sha1, const struct tth *tth)
{
	fi_gui_clear_details();

	fi_gui_append_detail(_("Filename"),
		lazy_filename_to_ui_string(filename));
	fi_gui_append_detail(_("Size"),
		nice_size(filesize, show_metric_units()));
	fi_gui_append_detail(_("SHA-1"),
		sha1 ? sha1_to_urn_string(sha1) : NULL);
	fi_gui_append_detail(_("Bitprint"),
		sha1 && tth ? bitprint_to_urn_string(sha1, tth) : NULL);
}

const char *
downloads_gui_status_string(const struct download *d)
{
	static char tmpstr[4096];
	const char *status = NULL;
	time_t now = tm_time();
	const fileinfo_t *fi;
	size_t rw;

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
						"/%u", (unsigned) guc_get_parq_dl_queue_length(d));
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
					(unsigned) (guc_get_parq_dl_retry_delay(d) - elapsed));
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
					(unsigned) guc_download_get_http_req_percent(d));
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
			const char *sha1_status;
			
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
				unsigned elapsed = fi->cha1_elapsed;
			
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
			guint32 avg_bps, bps;
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
			char buf[UINT64_DEC_BUFLEN];
			
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

const char *
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

	switch (current_page) {
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

	switch (current_page) {
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

	switch (current_page) {
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

	switch (current_page) {
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

static void
update_popup_downloads_copy_magnet(void)
{
	gtk_widget_set_sensitive(
		gui_popup_downloads_lookup("popup_downloads_copy_magnet"),
		NULL != fi_gui_get_file_at_cursor());
}

static void
downloads_gui_update_popup_downloads(void)
{
	update_popup_downloads_start_now();
	update_popup_downloads_queue();
	update_popup_downloads_resume();
	update_popup_downloads_pause();
	update_popup_downloads_copy_magnet();
}

static void
update_popup_downloads_copy_url(void)
{
	gtk_widget_set_sensitive(
		gui_popup_sources_lookup("popup_sources_copy_url"),
		NULL != fi_gui_get_source_at_cursor());
}

static void
downloads_gui_update_popup_sources(void)
{
	update_popup_downloads_copy_url();
}

#define SELECTED_FILES_FOREACH_START(item) { \
	GSList *iter_, *files_selected_; \
	fi_gui_files_freeze(); \
	files_selected_ = fi_gui_get_selected_files(TRUE); \
	iter_ = files_selected_; \
	for (iter_ = files_selected_; /*NOTHING */; iter_ = g_slist_next(iter_)) { \
		struct fileinfo_data *item; \
		if (NULL == iter_) { \
			g_slist_free(files_selected_); \
			files_selected_ = NULL; \
			fi_gui_files_thaw(); \
			break; \
		} \
		item = iter_->data;


#define SELECTED_FILES_FOREACH_END \
	} \
}

#define SELECTED_SOURCES_FOREACH_START(item) { \
	GSList *iter_, *sources_selected_; \
	fi_gui_files_freeze(); \
	sources_selected_ = fi_gui_get_selected_sources(TRUE); \
	iter_ = sources_selected_; \
	for (/* NOTHING*/; /* NOTHING */; iter_ = g_slist_next(iter_)) { \
		struct download *item; \
		if (NULL == iter_) { \
			g_slist_free(sources_selected_); \
			sources_selected_ = NULL; \
			fi_gui_files_thaw(); \
			break; \
		} \
		item = iter_->data; \
		download_check(item);


#define SELECTED_SOURCES_FOREACH_END \
	} \
}

static inline struct download *
selected_files_foreach_first(struct fileinfo_data *file)
{
	struct download *d;
	
	g_return_val_if_fail(file, NULL);

	/* NOTE: Traverse back-to-front because new items are appended */
	d = file->downloads ? hash_list_tail(file->downloads) : NULL;
	if (d) {
		download_check(d);
	}
	return d;
}

static inline struct download *
selected_files_foreach_next(struct fileinfo_data *file, struct download *d)
{
	g_return_val_if_fail(file, NULL);
	g_return_val_if_fail(d, NULL);
	download_check(d);

	/* NOTE: Traverse back-to-front because new items are appended */
	d = file->downloads ? hash_list_previous(file->downloads, d) : NULL;
	if (d) {
		download_check(d);
	}
	return d;
}

#define SELECTED_FILES_FOREACH_SOURCE_START(item) \
SELECTED_FILES_FOREACH_START(file_) { \
	struct download *item, *next_; \
	next_ = selected_files_foreach_first(file_); \
	while (next_) { \
		item = next_; \
		next_ = selected_files_foreach_next(file_, next_); \

#define SELECTED_FILES_FOREACH_SOURCE_END \
	} \
} SELECTED_FILES_FOREACH_END

void
on_popup_downloads_start_now_activate(GtkMenuItem *unused_menuitem,
	void *unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;
	
	SELECTED_FILES_FOREACH_SOURCE_START(d) {
		guc_download_start(d, TRUE);
	} SELECTED_FILES_FOREACH_SOURCE_END
}

void
on_popup_downloads_pause_activate(GtkMenuItem *unused_menuitem,
	void *unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	SELECTED_FILES_FOREACH_SOURCE_START(d) {
		guc_download_pause(d);
	} SELECTED_FILES_FOREACH_SOURCE_END
}

void
on_popup_downloads_resume_activate(GtkMenuItem *unused_menuitem,
	void *unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	SELECTED_FILES_FOREACH_SOURCE_START(d) {
		guc_download_resume(d);
	} SELECTED_FILES_FOREACH_SOURCE_END
}

void
on_popup_downloads_queue_activate(GtkMenuItem *unused_menuitem,
	void *unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	SELECTED_FILES_FOREACH_SOURCE_START(d) {
		guc_download_requeue(d);
	} SELECTED_FILES_FOREACH_SOURCE_END
}

static void
fi_gui_purge_selected_files(void)
{
	SELECTED_FILES_FOREACH_START(file) {
		guc_fi_purge(file->handle);
	} SELECTED_FILES_FOREACH_END
}

void
on_popup_downloads_abort_activate(GtkMenuItem *unused_menuitem,
	void *unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	fi_gui_purge_selected_files();
}

void
on_popup_downloads_copy_magnet_activate(GtkMenuItem *unused_menuitem,
	void *unused_udata)
{
	struct fileinfo_data *file;

	(void) unused_menuitem;
	(void) unused_udata;

	file = fi_gui_get_file_at_cursor();
	if (file) {
		char *magnet = fi_gui_file_get_magnet(file);
		clipboard_set_text(gui_main_window(), magnet);
		G_FREE_NULL(magnet);
	}
}

void
on_popup_downloads_config_cols_activate(GtkMenuItem *unused_menuitem,
	void *unused_udata)
{
    GtkWidget *cc, *widget;

	(void) unused_menuitem;
	(void) unused_udata;

	widget = fi_gui_files_widget();
	g_return_if_fail(widget);

    cc = gtk_column_chooser_new(widget);
    gtk_menu_popup(GTK_MENU(cc), NULL, NULL, NULL, NULL, 1,
		gtk_get_current_event_time());
}

/***
 *** popup_sources
 ***/


void
on_popup_sources_start_now_activate(GtkMenuItem *unused_menuitem,
	void *unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;
	
	SELECTED_SOURCES_FOREACH_START(d) {
		guc_download_start(d, TRUE);
	} SELECTED_SOURCES_FOREACH_END
}

void
on_popup_sources_push_activate(GtkMenuItem *unused_menuitem,
	void *unused_udata)
{
	gboolean send_pushes, firewalled;

	(void) unused_menuitem;
	(void) unused_udata;
	
   	gnet_prop_get_boolean_val(PROP_SEND_PUSHES, &send_pushes);
   	gnet_prop_get_boolean_val(PROP_IS_FIREWALLED, &firewalled);

   	if (!firewalled || send_pushes) {
		SELECTED_SOURCES_FOREACH_START(d) {
			guc_download_fallback_to_push(d, FALSE, TRUE);
		} SELECTED_SOURCES_FOREACH_END
	}
}

void
on_popup_sources_browse_host_activate(GtkMenuItem *unused_menuitem,
	void *unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	SELECTED_SOURCES_FOREACH_START(d) {
		search_gui_new_browse_host(download_hostname(d),
			download_addr(d), download_port(d), download_guid(d), NULL, 0);
	} SELECTED_SOURCES_FOREACH_END
}

void
on_popup_sources_forget_activate(GtkMenuItem *unused_menuitem,
	void *unused_udata)
{
	unsigned removed = 0;

	(void) unused_menuitem;
	(void) unused_udata;

	SELECTED_SOURCES_FOREACH_START(d) {
		removed += guc_download_remove_all_from_peer(download_guid(d),
						download_addr(d), download_port(d), FALSE);
	} SELECTED_SOURCES_FOREACH_END 

    statusbar_gui_message(15,
		NG_("Forgot %u download", "Forgot %u downloads", removed),
		removed);
}

void
on_popup_sources_connect_activate(GtkMenuItem *unused_menuitem,
	void *unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	SELECTED_SOURCES_FOREACH_START(d) {
		guc_node_add(download_addr(d), download_port(d), SOCK_F_FORCE);
	} SELECTED_SOURCES_FOREACH_END 
}

void
on_popup_sources_pause_activate(GtkMenuItem *unused_menuitem,
	void *unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	SELECTED_SOURCES_FOREACH_START(d) {
		guc_download_pause(d);
	} SELECTED_SOURCES_FOREACH_END 
}

void
on_popup_sources_resume_activate(GtkMenuItem *unused_menuitem,
	void *unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	SELECTED_SOURCES_FOREACH_START(d) {
		guc_download_resume(d);
	} SELECTED_SOURCES_FOREACH_END 
}

void
on_popup_sources_queue_activate(GtkMenuItem *unused_menuitem,
	void *unused_udata)
{
	(void) unused_menuitem;
	(void) unused_udata;

	SELECTED_SOURCES_FOREACH_START(d) {
		guc_download_requeue(d);
	} SELECTED_SOURCES_FOREACH_END 
}

void
on_popup_sources_copy_url_activate(GtkMenuItem *unused_menuitem,
	void *unused_udata)
{
	struct download *d;

	(void) unused_menuitem;
	(void) unused_udata;

   	d = fi_gui_get_source_at_cursor();
	if (d) {
		char *url = guc_download_build_url(d);
		clipboard_set_text(gui_main_window(), url);
		G_FREE_NULL(url);
	}
}

void
on_popup_sources_config_cols_activate(GtkMenuItem *unused_menuitem,
	void *unused_udata)
{
    GtkWidget *widget, *cc;

	(void) unused_menuitem;
	(void) unused_udata;

	widget = fi_gui_sources_widget();
	g_return_if_fail(widget);

    cc = gtk_column_chooser_new(GTK_WIDGET(widget));
    gtk_menu_popup(GTK_MENU(cc), NULL, NULL, NULL, NULL, 1,
		gtk_get_current_event_time());
}

/**
 * When the right mouse button is clicked on the active downloads
 * treeview, show the popup with the context menu.
 */
gboolean
on_files_button_press_event(GtkWidget *unused_widget,
	GdkEventButton *event, void *unused_udata)
{
	(void) unused_widget;
	(void) unused_udata;

	if (
		3 == event->button &&
		0 == (gtk_accelerator_get_default_mod_mask() & event->state)
	) {
		downloads_gui_update_popup_downloads();
    	gtk_menu_popup(GTK_MENU(gui_popup_downloads()), NULL, NULL, NULL, NULL,
        	event->button, event->time);
		return TRUE;
	}
	return FALSE;
}

gboolean
on_sources_button_press_event(GtkWidget *unused_widget,
	GdkEventButton *event, void *unused_udata)
{
	(void) unused_widget;
	(void) unused_udata;

	if (
		3 == event->button &&
		0 == (gtk_accelerator_get_default_mod_mask() & event->state)
	) {
		downloads_gui_update_popup_sources();
    	gtk_menu_popup(GTK_MENU(gui_popup_sources()), NULL, NULL, NULL, NULL,
        	event->button, event->time);
		return TRUE;
	}
	return FALSE;
}

static gboolean
fi_gui_file_visible(const struct fileinfo_data *file)
{
	switch (current_page) {
	case nb_downloads_page_active:
		return file->recv_count > 0;
	case nb_downloads_page_queued:
		return 0 == file->recv_count
			&& (file->actively_queued || file->passively_queued);
	case nb_downloads_page_finished:
		return file->size && file->done == file->size;
	case nb_downloads_page_seeding:
		return file->seeding;
	case nb_downloads_page_paused:
		return file->paused;
	case nb_downloads_page_incomplete:
		return file->done != file->size || 0 == file->size;
	case nb_downloads_page_all:
		return TRUE;
	case nb_downloads_page_num:
		break;
	}
	g_assert_not_reached();
	return TRUE;
}

static void
fi_gui_file_update_matched(struct fileinfo_data *file)
{
	g_return_if_fail(file);

	file->matched = !filter_regex
		|| 0 == regexec(filter_regex, file->filename, 0, NULL, 0);
}

/**
 * Fill in the cell data. Calling this will always break the data
 * it filled in last time!
 */
static void
fi_gui_file_set_filename(struct fileinfo_data *file)
{
    gnet_fi_info_t *info;

	g_return_if_fail(file);
	
    info = guc_fi_get_info(file->handle);
    g_return_if_fail(info);

	file->filename = atom_str_get(lazy_filename_to_ui_string(info->filename));
	guc_fi_free_info(info);
	fi_gui_file_update_matched(file);
}

static void
fi_gui_file_fill_status(struct fileinfo_data *file)
{
    gnet_fi_status_t status;

	g_return_if_fail(file);

    guc_fi_get_status(file->handle, &status);

	file->recv_rate = status.recv_last_rate;
	file->recv_count = status.recvcount;
	file->actively_queued = status.aqueued_count;
	file->passively_queued = status.pqueued_count;
	file->life_count = status.lifecount;

	file->uploaded = status.uploaded;
	file->size = status.size;
	file->done = status.done;
	file->progress = file->size ? filesize_per_1000(file->size, file->done) : 0;

	file->paused = 0 != status.paused;
	file->hashed = 0 != status.sha1_hashed;
	file->seeding = 0 != status.seeding;

	G_FREE_NULL(file->status);	
	file->status = g_strdup(guc_file_info_status_to_string(&status));
}

void
fi_gui_file_update_visibility(struct fileinfo_data *file)
{
	if (file->matched && fi_gui_file_visible(file)) {
		fi_gui_file_show(file);
	} else {
		fi_gui_file_hide(file);
	}
}

void
fi_gui_file_set_user_data(struct fileinfo_data *file, void *user_data)
{
	g_return_if_fail(file);
	file->user_data = user_data;
}

void *
fi_gui_file_get_user_data(const struct fileinfo_data *file)
{
	g_return_val_if_fail(file, NULL);
	return file->user_data;
}

const char *
fi_gui_file_get_filename(const struct fileinfo_data *file)
{
	g_return_val_if_fail(file, NULL);
	return file->filename;
}

unsigned
fi_gui_file_get_progress(const struct fileinfo_data *file)
{
	g_return_val_if_fail(file, 0);
	return file->progress / 10;
}

char *
fi_gui_file_get_file_url(const struct fileinfo_data *file)
{
	g_return_val_if_fail(file, NULL);
	return guc_file_info_get_file_url(file->handle);
}

char *
fi_gui_file_get_magnet(const struct fileinfo_data *file)
{
	g_return_val_if_fail(file, NULL);
	return guc_file_info_build_magnet(file->handle);
}

static void 
fi_gui_file_add(gnet_fi_t handle)
{
	static const struct fileinfo_data zero_data;
	struct fileinfo_data *file;
	
	g_return_if_fail(
		!g_hash_table_lookup(fi_handles, GUINT_TO_POINTER(handle)));

	file = walloc(sizeof *file);
	*file = zero_data;
	file->handle = handle;
	fi_gui_file_invalidate(file);
	g_hash_table_insert(fi_handles, GUINT_TO_POINTER(handle), file);
	fi_gui_file_set_filename(file);
	fi_gui_file_fill_status(file);
	fi_gui_file_show(file);
}

static void 
fi_gui_file_free(struct fileinfo_data *file)
{
	atom_str_free_null(&file->filename);
	G_FREE_NULL(file->status);
	wfree(file, sizeof *file);
}

static void 
fi_gui_file_remove(struct fileinfo_data *file)
{
	void *key;

	g_assert(file);

	key = GUINT_TO_POINTER(file->handle);
	g_hash_table_remove(fi_handles, key);
	g_hash_table_remove(fi_updates, key);
	g_assert(NULL == file->downloads);

	fi_gui_file_hide(file);
	fi_gui_file_free(file);
}

static void
fi_gui_clear_info(void)
{
	fi_gui_clear_details();
	fi_gui_clear_aliases();
	fi_gui_clear_sources();

    last_shown_valid = FALSE;
    vp_draw_fi_progress(last_shown_valid, last_shown);
}

static void
fi_gui_fi_removed(gnet_fi_t handle)
{
	struct fileinfo_data *file;
	void *key = GUINT_TO_POINTER(handle);
	
	if (last_shown_valid && handle == last_shown) {
		fi_gui_clear_info();
	}

	file = g_hash_table_lookup(fi_handles, key);
	g_return_if_fail(file);
	g_return_if_fail(handle == file->handle);

	fi_gui_file_remove(file);
}

static void
fi_gui_set_aliases(struct fileinfo_data *file)
{
    char **aliases;

	g_return_if_fail(file);
	
	fi_gui_clear_aliases();
    aliases = guc_fi_get_aliases(file->handle);
	g_return_if_fail(aliases);
	
	fi_gui_show_aliases((const char **) aliases);
    g_strfreev(aliases);
}

void
fi_gui_add_download(struct download *d)
{
	struct fileinfo_data *file;

	download_check(d);
	g_return_if_fail(d->file_info);

	file = g_hash_table_lookup(fi_handles,
				GUINT_TO_POINTER(d->file_info->fi_handle));
	g_return_if_fail(file);
	g_assert(d->file_info->fi_handle == file->handle);

	if (NULL == file->downloads) {
		file->downloads = hash_list_new(NULL, NULL);
	}
	g_return_if_fail(!hash_list_contains(file->downloads, d, NULL));

	/* 
	 * NOTE: Always append items so that we can jump through the hashlist with
	 * hash_list_previous().
	 */
	hash_list_append(file->downloads, d);

	if (last_shown_valid && last_shown == file->handle) {
		fi_gui_source_add(d);
	}
}

void
fi_gui_remove_download(struct download *d)
{
	struct fileinfo_data *file;

	download_check(d);
	g_return_if_fail(d->file_info);

	file = g_hash_table_lookup(fi_handles,
				GUINT_TO_POINTER(d->file_info->fi_handle));
	g_return_if_fail(file);
	g_assert(d->file_info->fi_handle == file->handle);

	g_return_if_fail(file->downloads);
	g_return_if_fail(hash_list_contains(file->downloads, d, NULL));

	hash_list_remove(file->downloads, d);
	if (0 == hash_list_length(file->downloads)) {
		hash_list_free(&file->downloads);
	}
	fi_gui_source_remove(d);
}


static void
fi_gui_set_sources(struct fileinfo_data *file)
{
	g_return_if_fail(file);

	if (file->downloads) {
		hash_list_iter_t *iter;

		iter = hash_list_iterator(file->downloads);
		while (hash_list_iter_has_next(iter)) {
			fi_gui_source_add(hash_list_iter_next(iter));
		}
		hash_list_iter_release(&iter);
	}
	downloads_gui_update_popup_sources();
}

static void
fi_gui_show_info(struct fileinfo_data *file)
{
    gnet_fi_info_t *info;

	fi_gui_clear_info();
	g_return_if_fail(file);

    info = guc_fi_get_info(file->handle);
	g_return_if_fail(info);

	fi_gui_set_details(info->filename, info->size, info->sha1, info->tth);
    guc_fi_free_info(info);

	fi_gui_set_aliases(file);
	fi_gui_set_sources(file);

    last_shown = file->handle;
    last_shown_valid = TRUE;
	vp_draw_fi_progress(last_shown_valid, last_shown);
}

void
fi_gui_files_cursor_update(void)
{
	struct fileinfo_data *file;

	file = fi_gui_get_file_at_cursor();
	if (file) {
		fi_gui_show_info(file);
	} else {
		fi_gui_clear_info();
	}
	downloads_gui_update_popup_downloads();
	downloads_gui_update_popup_sources();
}

static void
fi_gui_file_update(gnet_fi_t handle)
{
	struct fileinfo_data *file;

	file = g_hash_table_lookup(fi_handles, GUINT_TO_POINTER(handle));
	g_return_if_fail(file);

	fi_gui_file_fill_status(file);
	fi_gui_file_update_visibility(file);

	if (last_shown_valid && handle == last_shown) {
		vp_draw_fi_progress(last_shown_valid, last_shown);
	}
}

static void
fi_gui_fi_status_changed(gnet_fi_t handle)
{
	void *key = GUINT_TO_POINTER(handle);
	g_hash_table_insert(fi_updates, key, key);
}

static void
fi_gui_fi_status_changed_transient(gnet_fi_t handle)
{
	if (last_shown_valid && handle == last_shown) {
		fi_gui_fi_status_changed(handle);
	}
}

static gboolean
fi_gui_file_update_queued(void *key, void *unused_value, void *unused_udata)
{
	gnet_fi_t handle = GPOINTER_TO_UINT(key);

	(void) unused_value;
	(void) unused_udata;

  	fi_gui_file_update(handle);
	return TRUE; /* Remove the handle from the hashtable */
}

void
fi_gui_update_display(time_t unused_now)
{
	GtkWidget *widget;

	(void) unused_now;

	if (!main_gui_window_visible())
		return;

	widget = fi_gui_files_widget();
	g_return_if_fail(widget);

	if (!GTK_WIDGET_DRAWABLE(GTK_WIDGET(widget)))
		return;

	fi_gui_files_freeze();
	g_hash_table_foreach_remove(fi_updates, fi_gui_file_update_queued, NULL);
	fi_gui_files_thaw();
}

gboolean
on_files_key_press_event(GtkWidget *unused_widget,
	GdkEventKey *event, void *unused_udata)
{
	(void) unused_widget;
	(void) unused_udata;

	if (
		GDK_Delete == event->keyval &&
		0 == (gtk_accelerator_get_default_mod_mask() & event->state)
	) {
		switch (current_page) {
		case nb_downloads_page_finished:
		case nb_downloads_page_seeding:
			fi_gui_purge_selected_files();
			return TRUE;
		default:
			break;
		}
	}
	return FALSE;
}

void
fi_gui_download_set_status(struct download *d)
{
	fi_gui_source_update(d);
}

/**
 *	Update the server/vendor column of the active downloads treeview
 */
void
gui_update_download_server(struct download *d)
{
	fi_gui_source_update(d);
}

/**
 *	Update the range column of the active downloads treeview
 */
void
gui_update_download_range(struct download *d)
{
	fi_gui_source_update(d);
}

/**
 *	Update the size column of the active downloads treeview
 */
void
gui_update_download_size(struct download *d)
{
	fi_gui_source_update(d);
}

/**
 *	Update the host column of the active downloads treeview
 */
void
gui_update_download_host(struct download *d)
{
	fi_gui_source_update(d);
}

void
gui_download_updates_freeze(void)
{
	fi_gui_files_freeze();
}

void
gui_download_updates_thaw(void)
{
	fi_gui_files_thaw();
}

static void
fi_gui_fi_added(gnet_fi_t handle)
{
    fi_gui_file_add(handle);
	fi_gui_file_update(handle);
}

static inline unsigned
fileinfo_numeric_status(const struct fileinfo_data *file)
{
	unsigned v;

	v = file->progress;
	v |= file->seeding
			? (1 << 16) : 0;
	v |= file->hashed
			? (1 << 15) : 0;
	v |= file->size > 0 && file->size == file->done
			? (1 << 14) : 0;
	v |= file->recv_count > 0
			? (1 << 13) : 0;
	v |= (file->actively_queued || file->passively_queued)
			? (1 << 12) : 0;
	v |= file->paused
			? (1 << 11) : 0;
	v |= file->life_count > 0
			? (1 << 10) : 0;
	return v;
}

gboolean
on_details_key_press_event(GtkWidget *widget,
	GdkEventKey *event, void *unused_udata)
{
	(void) unused_udata;

	switch (event->keyval) {
	unsigned modifier;
	case GDK_c:
		modifier = gtk_accelerator_get_default_mod_mask() & event->state;
		if (GDK_CONTROL_MASK == modifier) {
			char *text = fi_gui_get_detail_at_cursor();
			clipboard_set_text(widget, text);
			G_FREE_NULL(text);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

int
fileinfo_data_cmp(const struct fileinfo_data *a, const struct fileinfo_data *b,
	int column)
{
	int ret = 0;

	switch ((enum c_fi) column) {
	case c_fi_filename:
		ret = strcmp(a->filename, b->filename);
		break;
	case c_fi_size:
		ret = CMP(a->size, b->size);
		break;
	case c_fi_uploaded:
		ret = CMP(a->uploaded, b->uploaded);
		break;
	case c_fi_progress:
		ret = CMP(a->progress, b->progress);
		ret = ret ? ret : CMP(a->done, b->done);
		break;
	case c_fi_rx:
		ret = CMP(a->recv_rate, b->recv_rate);
		ret = ret ? ret : CMP(a->recv_count > 0, b->recv_count > 0);
		break;
	case c_fi_done:
		ret = CMP(a->done, b->done);
		break;
	case c_fi_status:
		ret = CMP(fileinfo_numeric_status(a), fileinfo_numeric_status(b));
		break;
	case c_fi_sources:
		ret = CMP(a->recv_count, b->recv_count);
		if (0 == ret) {
			ret = CMP(a->actively_queued + a->passively_queued,
					b->actively_queued + b->passively_queued);
			if (0 == ret) {
				ret = CMP(a->life_count, b->life_count);
			}
		}
		break;
	case c_fi_num:
		g_assert_not_reached();
	}
	return ret;
}

unsigned
fi_gui_source_get_progress(const struct download *d)
{
	guint value;

	g_return_val_if_fail(d, 0);
	value = 100.0 * guc_download_source_progress(d);
	value = MIN(value, 100);
	return value;
}

const char *
fi_gui_source_column_text(const struct download *d, int column)
{
	const char *text;

	text = NULL;
	switch ((enum c_src) column) {
	case c_src_host:
		text = guc_download_get_hostname(d);
		break;
	case c_src_country:
		text = guc_download_get_country(d);
		break;
	case c_src_server:
		text = guc_download_get_vendor(d);
		break;
	case c_src_range:
		text = downloads_gui_range_string(d);
		break;
	case c_src_status:
		text = downloads_gui_status_string(d);
		break;
	case c_src_progress:
		text = source_progress_to_string(d);
		break;
	case c_src_num:
		g_assert_not_reached();
	}
	return text;
}

const char *
fi_gui_file_column_text(const struct fileinfo_data *file, int column)
{
	const char *text = NULL;

	switch ((enum c_fi) column) {
	case c_fi_filename:
		text = file->filename;
		break;
	case c_fi_size:
		text = 0 != file->size
				? compact_size(file->size, show_metric_units())
				: "?";
		break;
	case c_fi_uploaded:
		text = file->uploaded > 0 
				? compact_size(file->uploaded, show_metric_units())
				: "-";
		break;
	case c_fi_sources:
		{
			static char buf[256];

			gm_snprintf(buf, sizeof buf, "%u/%u/%u",
				file->recv_count,
				file->actively_queued + file->passively_queued,
				file->life_count);
			text = buf;
		}
		break;
	case c_fi_done:
		if (file->done && file->size) {
			text = short_size(file->done, show_metric_units());
		}
		break;
	case c_fi_rx:
		if (file->recv_count > 0) {
			text = short_rate(file->recv_rate, show_metric_units());
		}
		break;
	case c_fi_status:
		text = file->status;
		break;
	case c_fi_progress:
		if (file->done && file->size) {
			static char buf[256];

			gm_snprintf(buf, sizeof buf, "%u.%u",
				file->progress / 10, file->progress % 10);
			text = buf;
		}
		break;
	case c_fi_num:
		g_assert_not_reached();
	}
	return text;
}

static void
fi_handles_visualize(void *key, void *value, void *unused_udata)
{
	struct fileinfo_data *file;
	gnet_fi_t handle;
	
	g_assert(value);
	(void) unused_udata;
	
	handle = GPOINTER_TO_UINT(key);
	file = value;

	g_assert(handle == file->handle);
	fi_gui_file_invalidate(file);
	fi_gui_file_update_visibility(file);
}

void
fi_gui_files_visualize(void)
{
	g_hash_table_foreach(fi_handles, fi_handles_visualize, NULL);
}

static void
notebook_downloads_init_page(GtkNotebook *notebook, int page_num)
{
	GtkContainer *container;
	GtkWidget *widget;

	g_return_if_fail(notebook);

	container = GTK_CONTAINER(gtk_notebook_get_nth_page(notebook, page_num));
	g_return_if_fail(container);

	widget = fi_gui_files_widget_new();
	g_return_if_fail(widget);

	gtk_container_add(container, widget);
	gtk_widget_show_all(GTK_WIDGET(container));

	downloads_gui_update_popup_downloads();
}

static void
on_notebook_switch_page(GtkNotebook *notebook,
	GtkNotebookPage *unused_page, int page_num, void *unused_udata)
{
	(void) unused_udata;
	(void) unused_page;

	g_return_if_fail(UNSIGNED(page_num) < nb_downloads_page_num);
	g_return_if_fail(UNSIGNED(current_page) < nb_downloads_page_num);

	fi_gui_files_widget_destroy();

	current_page = page_num;
	notebook_downloads_init_page(notebook, current_page);
}

void
notebook_downloads_init(void)
{
	GtkNotebook *notebook;
	unsigned page;

	notebook = GTK_NOTEBOOK(gui_main_window_lookup("notebook_downloads"));
	while (gtk_notebook_get_nth_page(notebook, 0)) {
		gtk_notebook_remove_page(notebook, 0);
	}

	for (page = 0; page < nb_downloads_page_num; page++) {
		const char *title;
		GtkWidget *sw;

		title = NULL;
		switch (page) {
		case nb_downloads_page_active: 		title = _("Active"); break;
		case nb_downloads_page_queued: 		title = _("Queued"); break;
		case nb_downloads_page_paused: 		title = _("Paused"); break;
		case nb_downloads_page_incomplete: 	title = _("Incomplete"); break;
		case nb_downloads_page_finished: 	title = _("Finished"); break;
		case nb_downloads_page_seeding: 	title = _("Seeding"); break;
		case nb_downloads_page_all: 		title = _("All"); break;
		case nb_downloads_page_num: 		g_assert_not_reached(); break;
		}
		g_assert(title);

		sw = gtk_scrolled_window_new(NULL, NULL);
		gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(sw),
			GTK_SHADOW_IN);
		gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw),
			GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);

		gtk_notebook_append_page(notebook, sw, NULL);
		gtk_notebook_set_tab_label_text(notebook,
			gtk_notebook_get_nth_page(notebook, page),
			title);
		gtk_widget_show_all(sw);
	}
	gtk_notebook_set_scrollable(notebook, TRUE);
	gtk_notebook_set_current_page(notebook, current_page);
	notebook_downloads_init_page(notebook, current_page);

	gui_signal_connect(notebook, "switch-page", on_notebook_switch_page, NULL);
}

struct select_by_regex {
	regex_t expr;
	unsigned matches, total_nodes;
};

static void
fi_gui_regex_error(regex_t *expr, int error)
{
    char buf[1024];

	g_return_if_fail(expr);

	regerror(error, expr, buf, sizeof buf);
   	statusbar_gui_warning(15, "regex error: %s", lazy_locale_to_ui_string(buf));
}

static int 
fi_gui_select_by_regex_helper(struct fileinfo_data *file, void *user_data)
{
	struct select_by_regex *ctx;
	int ret;

	g_return_val_if_fail(file, FALSE);
	g_return_val_if_fail(user_data, FALSE);

	ctx = user_data;
	ctx->total_nodes++;

	ret = regexec(&ctx->expr, fi_gui_file_get_filename(file), 0, NULL, 0);
	if (0 == ret) {
		ctx->matches++;
		fi_gui_file_select(file);
	} else if (REG_NOMATCH != ret) {
		fi_gui_regex_error(&ctx->expr, ret);
		fi_gui_files_unselect_all();
		ctx->matches = 0;
		return TRUE;	/* stop */
	}
	return FALSE;
}

static void
fi_gui_select_by_regex(const char *regex)
{
	struct select_by_regex ctx;
    int ret, flags;

	ctx.matches = 0;
	ctx.total_nodes = 0;
	fi_gui_files_unselect_all();

	if (NULL == regex || '\0' == regex[0])
		return;

	flags = REG_EXTENDED | REG_NOSUB;
   	flags |= GUI_PROPERTY(download_select_regex_case) ? 0 : REG_ICASE;
    ret = regcomp(&ctx.expr, regex, flags);
   	if (ret) {
		fi_gui_regex_error(&ctx.expr, ret);
    } else {
		fi_gui_files_freeze();
		fi_gui_files_foreach(fi_gui_select_by_regex_helper, &ctx);
		fi_gui_files_thaw();

		statusbar_gui_message(15,
			NG_("Selected %u of %u download matching \"%s\".",
				"Selected %u of %u downloads matching \"%s\".",
				ctx.total_nodes),
			ctx.matches, ctx.total_nodes, regex);
	}
	regfree(&ctx.expr);
}

/**
 * Select all downloads that match given regex in editable.
 */
void
on_entry_downloads_select_regex_activate(GtkEditable *editable,
	void *unused_udata)
{
    char *regex;

	(void) unused_udata;

    regex = STRTRACK(gtk_editable_get_chars(GTK_EDITABLE(editable), 0, -1));
	g_return_if_fail(regex);

	fi_gui_select_by_regex(regex);
	G_FREE_NULL(regex);
}


static void
fi_handles_filter(void *key, void *value, void *unused_udata)
{
	struct fileinfo_data *file;
	gnet_fi_t handle;
	
	g_assert(value);
	(void) unused_udata;
	
	handle = GPOINTER_TO_UINT(key);
	file = value;

	g_assert(handle == file->handle);
	fi_gui_file_update_matched(file);
	fi_gui_file_update_visibility(file);
}

static void
filter_regex_clear(void)
{
	if (filter_regex) {
		regfree(filter_regex);
		G_FREE_NULL(filter_regex);
	}
}

static void
fi_gui_filter_by_regex(const char *expr)
{
	filter_regex_clear();

	g_return_if_fail(fi_handles);
	if (expr && '\0' != expr[0]) {
		int ret, flags;
		
		flags = REG_EXTENDED | REG_NOSUB;
   		flags |= GUI_PROPERTY(download_filter_regex_case) ? 0 : REG_ICASE;
		filter_regex = g_malloc(sizeof *filter_regex);
    	ret = regcomp(filter_regex, expr, flags);
		if (ret) {
			fi_gui_regex_error(filter_regex, ret);
			filter_regex_clear();
		}
	}
	fi_gui_files_freeze();
	g_hash_table_foreach(fi_handles, fi_handles_filter, NULL);
	fi_gui_files_thaw();
}

void
on_entry_downloads_filter_regex_activate(GtkEditable *editable,
	void *unused_udata)
{
    char *regex;

	(void) unused_udata;

    regex = STRTRACK(gtk_editable_get_chars(GTK_EDITABLE(editable), 0, -1));
	g_return_if_fail(regex);

	fi_gui_filter_by_regex(regex);
	G_FREE_NULL(regex);
}

void
fi_gui_common_init(void)
{
	fi_handles = g_hash_table_new(NULL, NULL);
	fi_updates = g_hash_table_new(NULL, NULL);

	notebook_downloads_init();

    guc_fi_add_listener(fi_gui_fi_added, EV_FI_ADDED, FREQ_SECS, 0);
    guc_fi_add_listener(fi_gui_fi_removed, EV_FI_REMOVED, FREQ_SECS, 0);
    guc_fi_add_listener(fi_gui_fi_status_changed, EV_FI_STATUS_CHANGED,
		FREQ_SECS, 0);
    guc_fi_add_listener(fi_gui_fi_status_changed_transient,
		EV_FI_STATUS_CHANGED_TRANSIENT, FREQ_SECS, 0);
}

static gboolean
fi_handles_shutdown(void *key, void *value, void *unused_data)
{
	struct fileinfo_data *file;
	gnet_fi_t handle;
	
	(void) unused_data;
	g_assert(value);
	
	handle = GPOINTER_TO_UINT(key);
	file = value;
	g_assert(handle == file->handle);
	fi_gui_file_free(file);

	return TRUE; /* Remove the handle from the hashtable */
}

void
fi_gui_common_shutdown(void)
{
    guc_fi_remove_listener(fi_gui_fi_removed, EV_FI_REMOVED);
    guc_fi_remove_listener(fi_gui_fi_added, EV_FI_ADDED);
    guc_fi_remove_listener(fi_gui_fi_status_changed, EV_FI_STATUS_CHANGED);

	filter_regex_clear();
	fi_gui_clear_info();
	g_hash_table_foreach_remove(fi_handles, fi_handles_shutdown, NULL);

	g_hash_table_destroy(fi_handles);
	fi_handles = NULL;
	g_hash_table_destroy(fi_updates);
	fi_updates = NULL;
}

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
download_gui_add(struct download *d)
{
	download_check(d);
	
	fi_gui_add_download(d);
	d->visible = TRUE;
}


/**
 *	Remove a download from the GUI.
 */
void
download_gui_remove(struct download *d)
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
	time_t now;

	download_check(d);

	now = tm_time();
    if (force || 0 != delta_time(now, d->last_gui_update)) {
		d->last_gui_update = now;
		fi_gui_download_set_status(d);
	}
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
 * Periodically called to update downloads display.
 */
void
downloads_gui_update_display(time_t unused_now)
{
	(void) unused_now;
}

/* vi: set ts=4 sw=4 cindent: */
