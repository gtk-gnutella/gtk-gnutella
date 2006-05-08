/*
 * $Id$
 *
 * Copyright (c) 2004, Christian Biere
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
 * Drop support - no dragging, just dropping.
 *
 * @author Christian Biere
 * @date 2004
 */

#include "gui.h"

RCSID("$Id$");

#include "drop.h"
#include "statusbar.h"
#include "search.h"

#include "if/bridge/ui2c.h"
#include "if/core/downloads.h"		/* URN_INDEX */
#include "if/core/guid.h"			/* blank_guid[] */
#include "if/gui_property_priv.h"

#include "lib/glib-missing.h"
#include "lib/tm.h"
#include "lib/url.h"
#include "lib/urn.h"
#include "lib/override.h"		/* Must be the last header included */

/*
 * Private prototypes;
 */

static gboolean handle_not_implemented(gchar *url);
static gboolean handle_magnet(gchar *url);

/*
 * Private data
 */

static const struct {
	const char * const proto;
	gboolean (* handler)(gchar *url);
} proto_handlers[] = {
	{ "http",	handle_not_implemented },
	{ "ftp",	handle_not_implemented },
	{ "magnet",	handle_magnet },
};

enum magnet_key {
	MAGNET_KEY_NONE,
	MAGNET_KEY_DISPLAY_NAME,	/* Display Name */
	MAGNET_KEY_KEYWORD_TOPIC,	/* Keyword Topic */
	MAGNET_KEY_EXACT_LENGTH,	/* eXact file Length */
	MAGNET_KEY_EXACT_SOURCE,	/* eXact Source */
	MAGNET_KEY_EXACT_TOPIC,		/* eXact Topic */
	
	NUM_MAGNET_KEYS
};

static const struct {
	const char * const key;
	const enum magnet_key id;
} magnet_keys[] = {
	{ "",		MAGNET_KEY_NONE },
	{ "dn",		MAGNET_KEY_DISPLAY_NAME },
	{ "kt",		MAGNET_KEY_KEYWORD_TOPIC },
	{ "xl",		MAGNET_KEY_EXACT_LENGTH },
	{ "xs",		MAGNET_KEY_EXACT_SOURCE },
	{ "xt",		MAGNET_KEY_EXACT_TOPIC },
};

struct magnet_download {
	gchar *display_name;
	gchar *sha1;
	filesize_t size;
	GSList *sources;
};

struct magnet_source {
	gchar *hostname;	/* g_malloc()ed */
	host_addr_t addr;
	guint16 port;
	gchar *sha1;		/* g_malloc()ed */
	gchar *uri;			/* g_malloc()ed */
};

/*
 * Private functions
 */

static enum magnet_key
magnet_key_get(const gchar *s)
{
	guint i;

	STATIC_ASSERT(G_N_ELEMENTS(magnet_keys) == NUM_MAGNET_KEYS);
	g_assert(s);
	
	for (i = 0; i < G_N_ELEMENTS(magnet_keys); i++) {
		if (0 == strcmp(magnet_keys[i].key, s))
			return magnet_keys[i].id;
	}

	return MAGNET_KEY_NONE;
}

static gboolean
handle_not_implemented(gchar *unused_url)
{
	(void) unused_url;

	statusbar_gui_warning(10,
			_("Support for this protocol is not yet implemented"));
	return FALSE;
}

static void
plus_to_space(gchar *s)
{
	gint c;
	gchar *p;

	for (p = s; (c = *p) != '\0'; p++)
		if (c == '+')
			*p = ' ';
}

static struct magnet_source *
magnet_parse_exact_source(const gchar *q, const struct magnet_download *dl)
{
	static const struct magnet_source zero_ms;
	struct magnet_source ms;
	const gchar *p, *ep, *host, *host_end;
	gchar digest[SHA1_RAW_SIZE];

	g_assert(q);
	g_assert(dl);

	ms = zero_ms;

	/* XXX: This should be handled elsewhere e.g., downloads.c in
	 *		a generic way. */

	p = is_strprefix(q, "http://");
	if (NULL == p) {
		statusbar_gui_warning(10, _("MAGNET URI contained source URL "
					"for an unsupported protocol"));
		/* Skip this parameter */
		return NULL;
	}

	if (!string_to_host_or_addr(p, &ep, &ms.addr)) {
		g_message("Expected host part");
		return NULL;
	}

	if (!is_host_addr(ms.addr)) {
		host = p;
		host_end = ep;
	} else {
		host = NULL;
		host_end = NULL;
	}
	p += ep - p;

	if (':' == *p) {
		const gchar *ep2;
		gint error;
		guint16 u;

		p++;
		u = parse_uint16(p, &ep2, 10, &error);
		if (error) {
			g_message("TCP port is out of range");
			/* Skip this parameter */
			return NULL;
		}

		ms.port = u;
		p += ep2 - p;
	} else {
		ms.port = 80;
	}

	if ('/' != *p) {
		g_message("Expected port followed by '/'");
		/* Skip this parameter */
		return NULL;
	}
	g_assert(*p == '/');

	ep = is_strprefix(p, "/uri-res/N2R?");
	if (ep) {
		p = ep;

		if (!urn_get_sha1(p, digest)) {
			g_message("Bad SHA1 in MAGNET URI (%s)", p);
			return NULL;
		}

		if (dl->sha1 && 0 != memcmp(digest, dl->sha1, sizeof digest)) {
			g_message("Different SHA1 in MAGNET URI (%s)", p);
			return NULL;
		}
		ms.sha1 = g_memdup(digest, sizeof digest);
	} else {
		ms.uri = g_strdup(p);
	}

	ms.hostname = host ? g_strndup(host, host_end - host) : NULL;

	return g_memdup(&ms, sizeof ms);
}

static gboolean
handle_magnet(gchar *url)
{
	static const struct magnet_download zero_dl;
	struct magnet_download dl;
	GSList *sl;
	gchar *p, *q, *next;

	dl = zero_dl;

	p = strchr(url, ':');
	g_assert(p);
	p++;

	if (*p != '?') {
		g_message("Invalid MAGNET URI");
		return FALSE;
	}
	p++;

	for (/* NOTHING */; p; p = next) {
		const gchar *name;

		q = strchr(p, '=');
		if (!q || p == q) {
			g_message("Invalid MAGNET URI");
			return FALSE;
		}
		name = p;
		g_assert((ssize_t) (q - p) > 0);

		*q++ = '\0';	/* Overwrite '=' and skip to next character */
		next = strchr(q, '&');
		if (next) {
			*next++ = '\0';
			if (*next == '\0')
				next = NULL;
		}
		plus_to_space(q);
		if (!url_unescape(q, TRUE)) {
			g_message("Invalidly encoded MAGNET URI");
			return FALSE;
		}

		/* q points to the value; p is free to use */

		switch (magnet_key_get(name)) {
		case MAGNET_KEY_DISPLAY_NAME:
			dl.display_name = q;
			break;

		case MAGNET_KEY_EXACT_SOURCE:
			{
				struct magnet_source *ms;
				
				ms = magnet_parse_exact_source(q, &dl);
				if (ms) {
					dl.sources = g_slist_prepend(dl.sources, ms);
					if (!dl.sha1)
						dl.sha1 = ms->sha1;
				}
			}
			break;

		case MAGNET_KEY_EXACT_TOPIC:
			{
				gchar digest[SHA1_RAW_SIZE];
				
				if (urn_get_sha1(q, digest)) {
					if (!dl.sha1) {
						dl.sha1 = g_memdup(digest, sizeof digest);
					}
				} else {
					statusbar_gui_warning(10,
						_("MAGNET URI contained unsupported exact topic."));
				}
			}
			break;

		case MAGNET_KEY_KEYWORD_TOPIC:
			search_gui_new_search(q, 0, NULL);
			break;

		case MAGNET_KEY_EXACT_LENGTH:
			{
				gint error;
				guint64 u;

				u = parse_uint64(q, NULL, 10, &error);
				if (!error)
					dl.size = u; 
			}
			break;

		case MAGNET_KEY_NONE:
			g_message("Unhandled parameter in MAGNET URI \"%s\"", name);
			break;
			
		case NUM_MAGNET_KEYS:
			g_assert_not_reached();
		}

	}
	dl.sources = g_slist_reverse(dl.sources);

	/* FIXME:
	 * As long as downloading of files without a known size is
	 * defective, we can only initiate downloads from magnets that
	 * specified a file length.
	 */

	if (dl.size > 0) {
		gchar *filename;
		gchar urn[256];

		filename = dl.display_name;
		if (!filename) {
			if (dl.sha1) {
				concat_strings(urn, sizeof urn,
					"urn:sha1:", sha1_base32(dl.sha1), (void *) 0);
				filename = urn;
			} else {
				filename = "magnet-download";
			}
		}

		g_message("Starting download from magnet");
		for (sl = dl.sources; sl != NULL; sl = g_slist_next(sl)) {
			struct magnet_source *ms = sl->data;
			host_addr_t addr;
			
			addr = is_host_addr(ms->addr) ? ms->addr : host_addr_set_ipv4(0);
			if (ms->port != 0 && (is_host_addr(addr) || ms->hostname)) {
				if (ms->uri) {
					guc_download_new_uri(filename, ms->uri, dl.size,
						addr, ms->port, blank_guid, ms->hostname,
						dl.sha1, tm_time(), FALSE, NULL, NULL, 0);
				} else if (ms->sha1 || dl.sha1) {
					/*
					 * This doesn't work either for hostnames because
					 * guc_download_new() doesn't handle it. 
					 */
					guc_download_new(filename, dl.size, URN_INDEX,
						addr, ms->port, blank_guid, ms->hostname,
						dl.sha1, tm_time(), FALSE, NULL, NULL, 0);
				} else {
					g_message("Unusable magnet source");
				}
			}
		}
	}
	
	for (sl = dl.sources; sl != NULL; sl = g_slist_next(sl)) {
		struct magnet_source *ms = sl->data;
		
		G_FREE_NULL(ms->hostname);
		G_FREE_NULL(ms->uri);
		G_FREE_NULL(ms->sha1);
		G_FREE_NULL(ms);
	}
	g_slist_free(dl.sources);
	dl.sources = NULL;

	return TRUE;
}


static void
drag_data_received(GtkWidget *unused_widget, GdkDragContext *dc,
	gint x, gint y, GtkSelectionData *data, guint info, guint stamp,
	gpointer unused_udata)
{
	gboolean succ = FALSE;

	(void) unused_widget;
	(void) unused_udata;

	if (gui_debug > 0)
		g_message("drag_data_received: x=%d, y=%d, info=%u, t=%u",
			x, y, info, stamp);
	if (data->length > 0 && data->format == 8) {
		gchar *p, *url = cast_to_gchar_ptr(data->data);
		size_t len;
		guint i;

		if (gui_debug > 0)
			g_message("drag_data_received: url=\"%s\"", url);


		p = strchr(url, ':');
		len = p ? p - url : 0;
		if (!p || (ssize_t) len < 1) {
			statusbar_gui_warning(10, _("Cannot handle the dropped data"));
			goto cleanup;
		}

		for (i = 0; i < G_N_ELEMENTS(proto_handlers); i++)
			if (is_strprefix(url, proto_handlers[i].proto)) {
				succ = proto_handlers[i].handler(url);
				break;
			}

		if (i == G_N_ELEMENTS(proto_handlers))
			statusbar_gui_warning(10, _("Protocol is not supported"));
	}

cleanup:

	gtk_drag_finish(dc, succ, FALSE, stamp);
}

/*
 * Public functions
 */

void
drop_init(void)
{
	static const GtkTargetEntry targets[] = {
		{ "STRING",		0, 23 },
		{ "text/plain", 0, 23 },
	};
	GtkWidget *w = GTK_WIDGET(main_window);

	gtk_drag_dest_set(w, GTK_DEST_DEFAULT_ALL, targets,
		G_N_ELEMENTS(targets), GDK_ACTION_COPY | GDK_ACTION_MOVE);

#ifdef USE_GTK2
	{
		static GtkClipboard *clipboard;
	
		g_return_if_fail(!clipboard);
		clipboard = gtk_clipboard_get(GDK_SELECTION_PRIMARY);
		g_return_if_fail(clipboard);
	}
	
	g_signal_connect(G_OBJECT(w), "drag-data-received",
		G_CALLBACK(drag_data_received), NULL);

	gtk_drag_dest_set_target_list(w, gtk_target_list_new(targets,
		G_N_ELEMENTS(targets)));
#endif /* USE_GTK2 */

#ifdef USE_GTK1
	gtk_signal_connect(GTK_OBJECT(w), "drag-data-received",
		drag_data_received, NULL);

	gtk_selection_add_targets(w, GDK_SELECTION_TYPE_STRING,
		targets, G_N_ELEMENTS(targets));
#endif /* USE_GTK1 */
	
}

void
drop_close(void)
{
	/* Nothing ATM */
}

/* vi: set ts=4 sw=4 cindent: */
