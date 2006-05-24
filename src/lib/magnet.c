/*
 * $Id$
 *
 * Copyright (c) 2006, Christian Biere
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
 * @ingroup lib
 * @file
 *
 * Handling of magnet links.
 *
 * @author Christian Biere
 * @date 2006
 */

#include "magnet.h"

RCSID("$Id$");

#include "lib/atoms.h"
#include "lib/glib-missing.h"
#include "lib/tm.h"
#include "lib/url.h"
#include "lib/urn.h"
#include "lib/walloc.h"
#include "lib/override.h"		/* Must be the last header included */

/*
 * Private prototypes;
 */

/*
 * Private data
 */

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
		if (0 == strcasecmp(magnet_keys[i].key, s))
			return magnet_keys[i].id;
	}

	return MAGNET_KEY_NONE;
}

static void
plus_to_space(gchar *s)
{
	while (s) {
		s = strchr(s, '+');
		if (s) {
			*s++ = ' ';
		}
	}
}

struct magnet_source *
magnet_parse_exact_source(const gchar *uri, const gchar **error_str)
{
	static const struct magnet_source zero_ms;
	struct magnet_source ms;
	const gchar *p, *ep, *host, *host_end;
	const gchar *error_dummy;

	g_return_val_if_fail(uri, NULL);

	if (!error_str) {
		error_str = &error_dummy;
	}

	ms = zero_ms;

	/* XXX: This should be handled elsewhere e.g., downloads.c in
	 *		a generic way. */

	p = is_strcaseprefix(uri, "http://");
	if (NULL == p) {
		*error_str =
			_("MAGNET URI contained source URL for an unsupported protocol");
		/* Skip this parameter */
		return NULL;
	}

	if (!string_to_host_or_addr(p, &ep, &ms.addr)) {
		*error_str = "Expected host part";
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
			*error_str = "TCP port is out of range";
			/* Skip this parameter */
			return NULL;
		}

		ms.port = u;
		p += ep2 - p;
	} else {
		ms.port = 80;
	}

	if ('/' != *p) {
		*error_str = "Expected port followed by '/'";
		/* Skip this parameter */
		return NULL;
	}
	g_assert(*p == '/');

	ep = is_strprefix(p, "/uri-res/N2R?");
	if (ep) {
		gchar digest[SHA1_RAW_SIZE];
		
		p = ep;
		if (!urn_get_sha1(p, digest)) {
			*error_str = "Bad SHA1 in MAGNET URI";
			return NULL;
		}
		ms.sha1 = atom_sha1_get(digest);
	} else {
		ms.path = atom_str_get(p);
	}

	if (host) {
		gchar *h = g_strndup(host, host_end - host);
		ms.hostname = atom_str_get(h);
		G_FREE_NULL(h);
	}

	return wcopy(&ms, sizeof ms);
}

static void
magnet_handle_key(struct magnet_resource *res,
	const gchar *name, const gchar *value)
{
	g_return_if_fail(res);
	g_return_if_fail(name);
	g_return_if_fail(value);
	
	switch (magnet_key_get(name)) {
	case MAGNET_KEY_DISPLAY_NAME:
		if (!res->display_name) {
			magnet_set_display_name(res, value);
		}
		break;

	case MAGNET_KEY_EXACT_SOURCE:
		{
			struct magnet_source *ms;

			ms = magnet_parse_exact_source(value, NULL);
			if (ms) {
				if (!res->sha1 && ms->sha1) {
					res->sha1 = atom_sha1_get(ms->sha1);
				}
				if (!ms->sha1 || sha1_eq(res->sha1, ms->sha1)) {
					res->sources = g_slist_prepend(res->sources, ms);
				} else {
					magnet_source_free(ms);
				}
			}
		}
		break;

	case MAGNET_KEY_EXACT_TOPIC:
		if (!magnet_set_exact_topic(res, value)) {
			g_message("MAGNET URI contained unsupported exact topic.");
		}
		break;

	case MAGNET_KEY_KEYWORD_TOPIC:
		magnet_add_search(res, value);
		break;

	case MAGNET_KEY_EXACT_LENGTH:
		{
			gint error;
			guint64 u;

			u = parse_uint64(value, NULL, 10, &error);
			if (!error) {
				magnet_set_filesize(res, u);
			}
		}
		break;

	case MAGNET_KEY_NONE:
		g_message("Unhandled parameter in MAGNET URI \"%s\"", name);
		break;

	case NUM_MAGNET_KEYS:
		g_assert_not_reached();
	}
}

struct magnet_resource * 
magnet_parse(const gchar *url, const gchar **error_str)
{
	static const struct magnet_resource zero_resource;
	struct magnet_resource res;
	const gchar *p, *next;

	res = zero_resource;

	p = is_strcaseprefix(url, "magnet:");
	if (!p) {
		*error_str = "Not a MAGNET URI";
		return NULL;
	}

	if ('?' != p[0]) {
		*error_str = "Invalid MAGNET URI";
		return NULL;
	}
	p++;

	for (/* NOTHING */; p && '\0' != p[0]; p = next) {
		enum magnet_key key;
		const gchar *endptr;
		gchar name[16]; /* Large enough to hold longest key we know */

		name[0] = '\0';
		endptr = strchr(p, '=');
		if (endptr && p != endptr) {
			size_t name_len;

			name_len = endptr - p;
			g_assert((ssize_t) name_len > 0);

			if (name_len < sizeof name) {  /* Ignore overlong key */
				strncat(name, p, name_len);
			}
			p = &endptr[1]; /* Point behind the '=' */
		}

		endptr = strchr(p, '&');
		if (!endptr) {
			endptr = strchr(p, '\0');
		}

		key = magnet_key_get(name);
		if (MAGNET_KEY_NONE == key) {
			g_message("Skipping unknown key in MAGNET URI (%s)", name);
		} else {
			gchar *value;
			size_t value_len;

			value_len = endptr - p;
			value = g_strndup(p, value_len);

			plus_to_space(value);
			if (url_unescape(value, TRUE)) {
				magnet_handle_key(&res, name, value);
			} else {
				g_message("Invalidly encoded value in MAGNET URI");
			}
			G_FREE_NULL(value);
		}

		while ('&' == endptr[0]) {
			endptr++;
		}
		next = endptr;
	}

	res.sources = g_slist_reverse(res.sources);
	res.searches = g_slist_reverse(res.searches);

	return wcopy(&res, sizeof res);
}

void
magnet_source_free(struct magnet_source *ms)
{
	if (ms) {
		atom_str_free_null(&ms->hostname);
		atom_str_free_null(&ms->path);
		atom_str_free_null(&ms->url);
		atom_sha1_free_null(&ms->sha1);
		wfree(ms, sizeof *ms);
	}
}

void
magnet_resource_free(struct magnet_resource *res)
{
	if (res) {
		GSList *sl;

		atom_str_free_null(&res->display_name);
		atom_sha1_free_null(&res->sha1);

		for (sl = res->sources; sl != NULL; sl = g_slist_next(sl)) {
			struct magnet_source *ms = sl->data;
			magnet_source_free(ms);
		}
		g_slist_free(res->sources);
		res->sources = NULL;

		for (sl = res->searches; sl != NULL; sl = g_slist_next(sl)) {
			gchar *s = sl->data;
			atom_str_free_null(&s);
		}
		g_slist_free(res->searches);
		res->searches = NULL;
		
		wfree(res, sizeof *res);
	}
}

struct magnet_resource *
magnet_resource_new(void)
{
	static const struct magnet_resource zero_resource;
	return wcopy(&zero_resource, sizeof zero_resource);
}

struct magnet_source *
magnet_source_new(void)
{
	static const struct magnet_source zero_source;
	return wcopy(&zero_source, sizeof zero_source);
}

void
magnet_add_source(struct magnet_resource *res, struct magnet_source *s)
{
	g_return_if_fail(res);
	g_return_if_fail(s);
	
	res->sources = g_slist_prepend(res->sources, s);
}

void
magnet_add_source_by_url(struct magnet_resource *res, const gchar *url)
{
	struct magnet_source *s;

	g_return_if_fail(res);
	g_return_if_fail(url);

	s = magnet_source_new();
	s->url = atom_str_get(url);
	magnet_add_source(res, s);
}

void
magnet_add_sha1_source(struct magnet_resource *res, const gchar *sha1,
	const host_addr_t addr, const guint16 port)
{
	struct magnet_source *s;

	g_return_if_fail(res);
	g_return_if_fail(sha1);
	g_return_if_fail(!res->sha1 || sha1_eq(res->sha1, sha1));
	g_return_if_fail(port > 0);

	if (!res->sha1) {
		magnet_set_sha1(res, sha1);
	}

	s = magnet_source_new();
	s->addr = addr;
	s->port = port;
	s->sha1 = atom_sha1_get(sha1);
	magnet_add_source(res, s);
}

void
magnet_add_search(struct magnet_resource *res, const gchar *search)
{
	g_return_if_fail(res);
	g_return_if_fail(search);

	res->searches = g_slist_prepend(res->searches, atom_str_get(search));
}


void
magnet_set_sha1(struct magnet_resource *res, const gchar *sha1)
{
	gchar *atom;

	g_return_if_fail(res);
	g_return_if_fail(sha1);

	atom = atom_sha1_get(sha1);
	atom_sha1_free_null(&res->sha1);
	res->sha1 = atom;
}

gboolean
magnet_set_exact_topic(struct magnet_resource *res, const gchar *topic)
{
	gchar digest[SHA1_RAW_SIZE];

	if (!urn_get_sha1(topic, digest)) {
		return FALSE;
	}
	if (!res->sha1) {
		magnet_set_sha1(res, digest);
	}
	return TRUE;
}

void
magnet_set_display_name(struct magnet_resource *res, const gchar *name)
{
	gchar *atom;

	g_return_if_fail(res);
	g_return_if_fail(name);

	atom = atom_str_get(name);
	atom_str_free_null(&res->display_name);
	res->display_name = atom;
}

void
magnet_set_filesize(struct magnet_resource *res, filesize_t size)
{
	res->size = size;
}

static inline void
magnet_append_item(GString **gs_ptr, gboolean escape_value,
	const gchar *key, const gchar *value)
{
	GString *gs;

	g_return_if_fail(gs_ptr);
	g_return_if_fail(*gs_ptr);
	g_return_if_fail(key);
	g_return_if_fail(value);

	gs = *gs_ptr;

	if (0 == gs->len) {
		gs = g_string_append(gs, "magnet:?");
	} else {
		gs = g_string_append_c(gs, '&');
	}
	gs = g_string_append(gs, key);
	gs = g_string_append_c(gs, '=');

	
	if (escape_value) {
		gchar *escaped;

		escaped = url_escape(value);
		gs = g_string_append(gs, escaped);
		if (escaped != value) {
			G_FREE_NULL(escaped);
		}
	} else {
		gs = g_string_append(gs, value);
	}

	*gs_ptr = gs;
}

gchar *
magnet_source_to_string(struct magnet_source *s)
{
	gchar *url;

	g_return_val_if_fail(s, NULL);

	if (s->url) {
		url = g_strdup(s->url);
	} else {
		const gchar *host;
		gchar port_buf[16];

		g_return_val_if_fail(0 != s->port, NULL);
		g_return_val_if_fail(s->hostname || is_host_addr(s->addr), NULL);
		g_return_val_if_fail(s->path || s->sha1, NULL);
		
		port_buf[0] = '\0';
		if (s->hostname) {
			host = s->hostname;
			if (80 != s->port) {
				gm_snprintf(port_buf, sizeof port_buf, ":%u",
					(unsigned) s->port);
			}
		} else {
			host = host_addr_port_to_string(s->addr, s->port);
		}
		if (s->path) {
			url = g_strconcat("http://", host, port_buf, s->path, (void *) 0);
		} else {
			url = g_strconcat("http://", host, port_buf,
					"/uri-res/N2R?urn:sha1:", sha1_base32(s->sha1),
					(void *) 0);
		}
	}

	return url;
}

gchar *
magnet_to_string(struct magnet_resource *res)
{
	GString *gs;
	GSList *sl;

	g_return_val_if_fail(res, NULL);
	
	gs = g_string_new(NULL);
	if (res->display_name) {
		magnet_append_item(&gs, TRUE, "dn", res->display_name);
	}
	if (0 != res->size) {
		gchar buf[UINT64_DEC_BUFLEN];

		uint64_to_string_buf(res->size, buf, sizeof buf);
		magnet_append_item(&gs, FALSE, "xl", buf);
	}
	if (res->sha1) {
		gchar buf[64];

		concat_strings(buf, sizeof buf, "urn:sha1:", sha1_base32(res->sha1),
			(void *) 0);
		magnet_append_item(&gs, FALSE, "xt", buf);
	}

	for (sl = res->sources; NULL != sl; sl = g_slist_next(sl)) {
		gchar *url;

		url = magnet_source_to_string(sl->data);
		magnet_append_item(&gs, TRUE, "xs", url);
		G_FREE_NULL(url);
	}

	for (sl = res->searches; NULL != sl; sl = g_slist_next(sl)) {
		magnet_append_item(&gs, TRUE, "kt", sl->data);
	}

	return gm_string_finalize(gs);
}

/* vi: set ts=4 sw=4 cindent: */
