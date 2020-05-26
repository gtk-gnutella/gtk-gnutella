/*
 * Copyright (c) 2001-2003, Richard Eckart
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

#include "gui.h"

#include "uploads.h"			/* For upload_row_data_t */
#include "uploads_common.h"
#include "search.h"
#include "settings.h"
#include "notebooks.h"

#include "if/gui_property.h"
#include "if/gnet_property.h"
#include "if/core/uploads.h"
#include "if/bridge/ui2c.h"

#include "lib/concat.h"
#include "lib/host_addr.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/tm.h"

#include "lib/override.h"		/* Must be the last header included */

#define IO_STALLED	60	/**< If nothing exchanged after that many secs */
#define UPDATE_MIN	60	/**< Update screen every minute at least */

/**
 *
 * @returns a floating point value from [0:1] which indicates
 * the total progress of the upload.
 */
gdouble
uploads_gui_progress(const gnet_upload_status_t *u,
	const upload_row_data_t *data)
{
	gdouble progress = 0.0;

	if (u->pos < data->range_start) /* No progress yet */
		return 0.0;

	switch (u->status) {
    case GTA_UL_HEADERS:
    case GTA_UL_EXPECTING:
    case GTA_UL_WAITING:
    case GTA_UL_ABORTED:
	case GTA_UL_QUEUED:
    case GTA_UL_QUEUE:
    case GTA_UL_QUEUE_WAITING:
	case GTA_UL_PUSH_RECEIVED:
		progress = 0.0;
		break;
    case GTA_UL_CLOSED:
	case GTA_UL_COMPLETE:
		progress = 1.0;
		break;
	case GTA_UL_SENDING:
		{
			filesize_t requested, done;

			requested = data->range_end - data->range_start + 1;
			done = requested > 0 ? u->pos - data->range_start : 0;
			progress = filesize_per_10000(requested, done) / 10000.0;
		}
		break;
	}
	return progress;
}

/**
 * @return a pointer to a static buffer containing a string which
 * describes the current status of the upload.
 */
const gchar *
uploads_gui_status_str(const gnet_upload_status_t *u,
	const upload_row_data_t *data)
{
	static gchar tmpstr[256];

	if (u->pos < data->range_start)
		return _("No output yet..."); /* Never wrote anything yet */

    switch (u->status) {
    case GTA_UL_PUSH_RECEIVED:
        return _("Got push, connecting back...");

    case GTA_UL_COMPLETE:
		{
			time_delta_t d = delta_time(data->last_update, data->start_date);
			time_delta_t x = delta_time(data->last_update,
								MAX(data->send_date, data->start_date));
	        filesize_t requested = data->range_end - data->range_start + 1;
			size_t rw;

			rw = str_bprintf(ARYLEN(tmpstr),
				"%s (%s in %s) %s %s#%u", _("Completed"),
				short_rate(requested / MAX(x, 1), show_metric_units()),
				short_time(x),
				short_time2(d),
				u->parq_quick ? _("(quick) ") : "",
				u->reqnum);

			if (u->error_count)
				rw += str_bprintf(ARYPOSLEN(tmpstr, rw),
					_(" E=%u"), u->error_count);
		}
        break;

    case GTA_UL_SENDING:
		{
			/* Time Remaining at the current rate, in seconds  */
			filesize_t tr = (data->range_end + 1 - u->pos) / MAX(1, u->avg_bps);
			double p = uploads_gui_progress(u, data);
			time_t now = tm_time();
			bool stalled = delta_time(now, data->last_update) > IO_STALLED;
			char pbuf[32];
			char dbuf[32];
			size_t rw;

			if (u->bw_penalty != 0)
				str_bprintf(ARYLEN(dbuf), " [/%u]", 1U << u->bw_penalty);

			str_bprintf(ARYLEN(pbuf), "%5.02f%% ", p * 100.0);
			rw = str_bprintf(ARYLEN(tmpstr),
				_("%s(%s)%s TR: %s %s#%u"),
				p > 1.0 ? pbuf : "",
				stalled ? _("stalled")
					: short_rate(u->bps, show_metric_units()),
				u->bw_penalty != 0 ? dbuf : "",
				short_time(tr),
				u->parq_quick ? _("(quick) ") : "",
				u->reqnum);

			if (u->error_count)
				rw += str_bprintf(ARYPOSLEN(tmpstr, rw),
					_(" E=%u"), u->error_count);
		}
		break;

    case GTA_UL_HEADERS:
        return _("Waiting for headers...");

    case GTA_UL_EXPECTING:
		if (u->error_count)
			str_bprintf(ARYLEN(tmpstr),
				_("%s %s#%u E=%u"), _("Waiting for further request..."),
				u->parq_quick ? _("(quick) ") : "", u->reqnum, u->error_count);
		else
			str_bprintf(ARYLEN(tmpstr),
				"%s %s#%u", _("Waiting for further request..."),
				u->parq_quick ? _("(quick) ") : "", u->reqnum);
		break;

    case GTA_UL_WAITING:
        return _("Reading follow-up request...");

    case GTA_UL_ABORTED:
        return _("Transmission aborted");

    case GTA_UL_CLOSED:
        return _("Transmission complete");

	case GTA_UL_QUEUED:		/* Actively queued */
		{
			guint32 max_up, cur_up;
			gboolean queued;
			guint available = 0;
			gchar tbuf[64];
			size_t rw;

			gnet_prop_get_guint32_val(PROP_MAX_UPLOADS, &max_up);
			gnet_prop_get_guint32_val(PROP_UL_RUNNING, &cur_up);

			if (cur_up < max_up)
				available = max_up - cur_up;

			/*
			 * We'll flag as "Waiting" instead of "Queued" uploads
			 * that are actively queued and whose position is low
			 * enough to possibly get scheduled at the next request,
			 * given the amount of free slots.
			 *		--RAM, 2007-08-21
			 */

			queued = u->parq_position > available;

			if (u->parq_retry > 0) {
				str_bprintf(ARYLEN(tbuf), " %s,", short_time(u->parq_retry));
			} else {
				tbuf[0] = '\0';
			}

			rw = str_bprintf(ARYLEN(tmpstr),
						_("%s [%d] (slot %d/%d)%s %s %s"),
						u->parq_frozen ? _("Frozen") :
						queued ? _("Queued") : _("Waiting"),
						u->parq_queue_no,
						u->parq_position,
						u->parq_size,
						tbuf,
						_("lifetime:"),
						short_time(u->parq_lifetime));

			if (u->error_count)
				rw += str_bprintf(ARYPOSLEN(tmpstr, rw),
					_(" E=%u"), u->error_count);
		}
		break;

    case GTA_UL_QUEUE:
        /*
         * PARQ wants to inform a client that action from the client its side
         * is wanted. So it is trying to connect back.
         *      -- JA, 15/04/2003
         */
        return _("Sending QUEUE, connecting back...");

    case GTA_UL_QUEUE_WAITING:
        /*
         * PARQ made a connect back because some action from the client is
         * wanted. The connection is established and now waiting for some action
         *      -- JA, 15/04/2003
         */
		return _("Sent QUEUE, waiting for headers...");
	}

    return tmpstr;
}

/**
 * @return whether the entry for the upload `ul' should be removed
 * from the UI with respect to the configured behaviour.
 */
gboolean
upload_should_remove(time_t now, const upload_row_data_t *ul)
{
	property_t prop = 0;

	g_assert(NULL != ul);

	switch (ul->status) {
	case GTA_UL_COMPLETE:
		prop = PROP_AUTOCLEAR_COMPLETED_UPLOADS;
		break;
	case GTA_UL_CLOSED:
	case GTA_UL_ABORTED:
		prop = PROP_AUTOCLEAR_FAILED_UPLOADS;
		break;
	case GTA_UL_PUSH_RECEIVED:
	case GTA_UL_SENDING:
	case GTA_UL_HEADERS:
	case GTA_UL_WAITING:
	case GTA_UL_EXPECTING:
	case GTA_UL_QUEUED:
	case GTA_UL_QUEUE:
	case GTA_UL_QUEUE_WAITING:
		break;
	}

	if (0 != prop) {
		guint32 val;
		time_delta_t grace;

		gnet_prop_get_guint32_val(PROP_ENTRY_REMOVAL_TIMEOUT, &val);
		grace = val;

		if (delta_time(now, ul->last_update) > grace) {
			gboolean auto_remove;

			gui_prop_get_boolean_val(prop, &auto_remove);
			return auto_remove;
		}
	}

	return FALSE;
}

/**
 * @return A pointer to a static buffer holding the host address as string.
 */
const gchar *
uploads_gui_host_string(const gnet_upload_info_t *u)
{
	static gchar buf[1024];
	const gchar *peer;

	if (u->gnet_port && is_host_addr(u->gnet_addr)) {
		peer = host_addr_port_to_string(u->gnet_addr, u->gnet_port);
	} else {
		peer = NULL;
	}

	concat_strings(ARYLEN(buf),
		host_addr_to_string(u->addr),
		u->encrypted ? (u->tls_upgraded ? " (e) " : " (E) ") : "",
		u->g2 ? " [G2] " : "",
		peer ? " <" : "",
		peer ? peer : "",
		peer ? ">"  : "",
		NULL_PTR);

	return buf;
}

/**
 * Initiate a browse host of the uploading host.
 */
void
uploads_gui_browse_host(host_addr_t addr, guint16 port)
{
	if (host_addr_is_routable(addr) && port != 0)
		search_gui_new_browse_host(NULL, addr, port, NULL, NULL, 0);
}

static gboolean
uploads_gui_is_visible(void)
{
	return main_gui_window_visible() &&
		nb_main_page_uploads == main_gui_notebook_get_page();
}

gboolean
uploads_gui_update_required(time_t now)
{
	static time_t last_update;
	time_delta_t delta;

	/*
	 * Usually don't perform updates if nobody is watching.  However,
	 * we do need to perform periodic cleanup of dead entries or the
	 * memory usage will grow.  Perform an update every UPDATE_MIN minutes
	 * at least.
	 *		--RAM, 28/12/2003
	 */

	delta = last_update ? delta_time(now, last_update) : UPDATE_MIN;
	if (0 == delta || (delta < UPDATE_MIN && !uploads_gui_is_visible()))
		return FALSE;

	last_update = now;
	return TRUE;
}

/* vi: set ts=4 sw=4 cindent: */
