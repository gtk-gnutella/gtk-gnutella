/*
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
 * @todo TODO: Utilize hashlists to prevent duplicate sources.
 *
 * @author Christian Biere
 * @date 2006
 */

#include "common.h"

#include "magnet.h"

#include "ascii.h"
#include "atoms.h"
#include "concat.h"
#include "gnet_host.h"
#include "halloc.h"
#include "once.h"
#include "parse.h"
#include "sequence.h"
#include "str.h"
#include "stringify.h"
#include "tm.h"
#include "tokenizer.h"
#include "unsigned.h"
#include "url.h"
#include "urn.h"
#include "utf8.h"
#include "walloc.h"

#include "if/core/guid.h"

#include "override.h"		/* Must be the last header included */

/*
 * Private prototypes;
 */

/*
 * Private data
 */

enum magnet_key {
	MAGNET_KEY_NONE = 0,
	MAGNET_KEY_DISPLAY_NAME,		/* Display Name */
	MAGNET_KEY_KEYWORD_TOPIC,		/* Keyword Topic */
	MAGNET_KEY_EXACT_LENGTH,		/* eXact file Length */
	MAGNET_KEY_ALTERNATE_SOURCE,	/* Alternate Source */
	MAGNET_KEY_EXACT_SOURCE,		/* eXact Source */
	MAGNET_KEY_EXACT_TOPIC,			/* eXact Topic */
	MAGNET_KEY_PARQ_ID,				/* PARQ ID */
	MAGNET_KEY_GUID,				/* Servent GUID */
	MAGNET_KEY_VENDOR,				/* Servent vendor */
	MAGNET_KEY_DHT,					/* Servent known to publish in the DHT */
	MAGNET_KEY_G2,					/* Servent is a G2 node */

	NUM_MAGNET_KEYS
};

static tokenizer_t magnet_keys[] = {
	/* Must be sorted alphabetically */
	{ "",			MAGNET_KEY_NONE },
	{ "as",			MAGNET_KEY_ALTERNATE_SOURCE },
	{ "dn",			MAGNET_KEY_DISPLAY_NAME },
	{ "kt",			MAGNET_KEY_KEYWORD_TOPIC },
	{ "x.dht",		MAGNET_KEY_DHT },
	{ "x.g2",		MAGNET_KEY_G2 },
	{ "x.guid",		MAGNET_KEY_GUID },
	{ "x.parq-id",	MAGNET_KEY_PARQ_ID },
	{ "x.vndr",		MAGNET_KEY_VENDOR },
	{ "xl",			MAGNET_KEY_EXACT_LENGTH },
	{ "xs",			MAGNET_KEY_EXACT_SOURCE },
	{ "xt",			MAGNET_KEY_EXACT_TOPIC },

	/* Above line left blank for "!}sort" under vi */
};

/*
 * Private functions
 */

static void
clear_error_str(const char ***error_str)
{
	if (NULL == *error_str) {
		static const char *error_dummy;
		*error_str = &error_dummy;
	}
	**error_str = NULL;
}

static void
free_proxies_list(pslist_t *sl)
{
	pslist_foreach(sl, gnet_host_free_item, NULL);
	pslist_free(sl);
}

static once_flag_t magnet_keys_checked;

static void G_COLD
magnet_key_check(void)
{
	TOKENIZE_CHECK_SORTED_WITH(magnet_keys, ascii_strcasecmp);
}

static enum magnet_key
magnet_key_get(const char *s)
{
	STATIC_ASSERT(G_N_ELEMENTS(magnet_keys) == NUM_MAGNET_KEYS);
	g_assert(s != NULL);

	ONCE_FLAG_RUN(magnet_keys_checked, magnet_key_check);

	return TOKENIZE_WITH(s, ascii_strcasecmp, magnet_keys);
}

static void
plus_to_space(char *s)
{
	while (s) {
		s = strchr(s, '+');
		if (s) {
			*s++ = ' ';
		}
	}
}

static struct magnet_source *
magnet_parse_path(const char *path, const char **error_str)
{
	static const struct magnet_source zero_ms;
	struct magnet_source ms;
	const char *p, *endptr;

	clear_error_str(&error_str);
	g_return_val_if_fail(path, NULL);

	ms = zero_ms;
	p = path;

	if ('/' != *p) {
		*error_str = "Expected path starting with '/'";
		/* Skip this parameter */
		return NULL;
	}
	g_assert(*p == '/');

	endptr = is_strprefix(p, "/uri-res/N2R?");
	if (endptr) {
		struct sha1 sha1;

		p = endptr;
		if (!urn_get_sha1(p, &sha1)) {
			*error_str = "Bad SHA1 in MAGNET URI";
			return NULL;
		}
		ms.sha1 = atom_sha1_get(&sha1);
	} else {
		ms.path = atom_str_get(p);
	}

	return wcopy(&ms, sizeof ms);
}

static const char *
magnet_parse_host_port(const char *hostport,
	host_addr_t *addr, uint16 *port, const char **host, const char **host_end,
	const char **error_str)
{
	const char *p;
	const char *endptr;

	clear_error_str(&error_str);
	g_return_val_if_fail(hostport, NULL);

	p = hostport;

	if (!string_to_host_or_addr(p, &endptr, addr)) {
		*error_str = "Expected host part";
		return NULL;
	}

	if (is_host_addr(*addr)) {
		if (host)     *host = NULL;
		if (host_end) *host_end = NULL;
	} else {
		if (host)     *host = p;
		if (host_end) *host_end = endptr;
	}
	p += endptr - p;

	if (':' == *p) {
		const char *ep2;
		int error;
		uint16 u;

		p++;
		u = parse_uint16(p, &ep2, 10, &error);
		if (error) {
			*error_str = "TCP port is out of range";
			/* Skip this parameter */
			return NULL;
		}

		*port = u;
		p += ep2 - p;
	} else {
		*port = 80;
	}

	return p;
}

static struct magnet_source *
magnet_parse_location(const char *uri, const char **error_str)
{
	struct magnet_source *ms;
	const char *p, *host, *host_end;
	host_addr_t addr;
	uint16 port;

	clear_error_str(&error_str);
	g_return_val_if_fail(uri, NULL);

	p = uri;

	p = magnet_parse_host_port(uri, &addr, &port, &host, &host_end, error_str);
	if (NULL == p)
		return NULL;

	ms = magnet_parse_path(p, error_str);
	if (NULL == ms)
		return NULL;

	if (host) {
		char *h = h_strndup(host, host_end - host);
		ms->hostname = atom_str_get(h);
		HFREE_NULL(h);
	}

	ms->addr = addr;
	ms->port = port;

	return ms;
}

static bool
magnet_parse_addr_list(const char *proxies,
	const char **endptr, pslist_t **list, const char **error_str)
{
	pslist_t *sl = NULL;
	const char *p;

	clear_error_str(&error_str);
	g_return_val_if_fail(proxies, FALSE);

	p = proxies;

	while (*p == ':') {
		host_addr_t addr;
		uint16 port;
		gnet_host_t *host;

		p = magnet_parse_host_port(p+1, &addr, &port, NULL, NULL, error_str);
		if (NULL == p)
			goto cleanup;

		host = gnet_host_new(addr, port);
		sl = pslist_prepend(sl, host);		/* Will reverse list below */
	}

	sl = pslist_reverse(sl);		/* Keep order of listed push-proxies */
	*endptr = p;

	*list = sl;
	return TRUE;

cleanup:
	free_proxies_list(sl);
	return FALSE;
}

static struct magnet_source *
magnet_parse_proxy_location(const char *uri, const char **error_str)
{
	struct magnet_source *ms;
	const char *p, *endptr = NULL;
	pslist_t *sl = NULL;

	clear_error_str(&error_str);
	g_return_val_if_fail(uri, NULL);

	p = uri;

	/*
	 * If starts with a '/', then we have no push-proxy following the GUID.
	 */

	if (*p == '/') {
		endptr = p;
		goto path;
	}

	if (*p != ':') {
		*error_str = "Expected / or : following the GUID";
		return NULL;
	}

	if (!magnet_parse_addr_list(uri, &endptr, &sl, error_str))
		return NULL;

	/* FALL THROUGH */

path:
	ms = magnet_parse_path(endptr, error_str);
	if (NULL == ms) {
		free_proxies_list(sl);
		return NULL;
	}

	ms->proxies = sl;		/* Perfectly OK to be NULL */

	return ms;
}

static struct magnet_source *
magnet_parse_http_source(const char *uri, const char **error_str)
{
	const char *p;

	clear_error_str(&error_str);
	g_return_val_if_fail(uri, NULL);

	p = is_strcaseprefix(uri, "http://");
	g_return_val_if_fail(p, NULL);

	return magnet_parse_location(p, error_str);
}

static struct magnet_source *
magnet_parse_push_source(const char *uri, const char **error_str)
{
	struct magnet_source *ms;
	const char *p, *endptr;
	struct guid guid;

	clear_error_str(&error_str);
	g_return_val_if_fail(uri, NULL);

	p = is_strprefix(uri, "push://");
	g_return_val_if_fail(p, NULL);

	endptr = strchr(p, ':');		/* First push-proxy host */
	if (NULL == endptr || GUID_HEX_SIZE != (endptr - p))
		endptr = strchr(p, '/');	/* No push-proxy host */

	if (
		NULL == endptr ||
		GUID_HEX_SIZE != (endptr - p) ||
		!hex_to_guid(p, &guid)
	) {
		*error_str = "Bad GUID in push source";
		return NULL;
	}

	ms = magnet_parse_proxy_location(endptr, error_str);
	if (ms) {
		ms->guid = atom_guid_get(&guid);
	}
	return ms;
}

struct magnet_source *
magnet_parse_exact_source(const char *uri, const char **error_str)
{
	clear_error_str(&error_str);
	g_return_val_if_fail(uri, NULL);

	/* TODO: This should be handled elsewhere e.g., downloads.c in
	 *		a generic way. */

	if (is_strcaseprefix(uri, "http://")) {
		return magnet_parse_http_source(uri, error_str);
	} else if (is_strcaseprefix(uri, "push://")) {
		return magnet_parse_push_source(uri, error_str);
	} else {
		*error_str =
			_("MAGNET URI contained source URL for an unsupported protocol");
		/* Skip this parameter */
		return NULL;
	}
}

static void
magnet_handle_key(struct magnet_resource *res,
	const char *name, const char *value)
{
	char *to_free = NULL;

	g_return_if_fail(res);
	g_return_if_fail(name);
	g_return_if_fail(value);

	if (!utf8_is_valid_string(value)) {
		const char *encoding;
		char *result;

		g_message("MAGNET URI key \"%s\" is not UTF-8 encoded", name);

		if (MAGNET_KEY_DISPLAY_NAME != magnet_key_get(name))
			return;

		result = unknown_to_utf8(value, &encoding);
		if (result != value) {
			to_free = result;
		}
		value = result;
		g_message("assuming MAGNET URI key \"%s\" is %s encoded",
			name, encoding);
	}

	switch (magnet_key_get(name)) {
	case MAGNET_KEY_DISPLAY_NAME:
		if (!res->display_name) {
			magnet_set_display_name(res, value);
		}
		break;

	case MAGNET_KEY_ALTERNATE_SOURCE:
	case MAGNET_KEY_EXACT_SOURCE:
		{
			struct magnet_source *ms;
			const char *error;

			ms = magnet_parse_exact_source(value, &error);
			if (ms) {
				if (!res->sha1 && ms->sha1) {
					res->sha1 = atom_sha1_get(ms->sha1);
				}
				if (!ms->sha1 || sha1_eq(res->sha1, ms->sha1)) {
					res->sources = pslist_prepend(res->sources, ms);
				} else {
					magnet_source_free(&ms);
				}
			} else {
				g_message("could not parse source \"%s\" in MAGNET URI: %s",
					value, NULL_STRING(error));
			}
		}
		break;

	case MAGNET_KEY_EXACT_TOPIC:
		if (!magnet_set_exact_topic(res, value)) {
			g_message("MAGNET URI contained unsupported exact topic \"%s\"",
				value);
		}
		break;

	case MAGNET_KEY_KEYWORD_TOPIC:
		magnet_add_search(res, value);
		break;

	case MAGNET_KEY_EXACT_LENGTH:
		{
			int error;
			uint64 u;

			u = parse_uint64(value, NULL, 10, &error);
			if (!error) {
				magnet_set_filesize(res, u);
			}
		}
		break;

	case MAGNET_KEY_PARQ_ID:
		magnet_set_parq_id(res, value);
		break;

	case MAGNET_KEY_VENDOR:
		magnet_set_vendor(res, value);
		break;

	case MAGNET_KEY_GUID:
		magnet_set_guid(res, value);
		break;

	case MAGNET_KEY_DHT:
		{
			int error;
			uint8 u;

			u = parse_uint8(value, NULL, 10, &error);
			if (!error) {
				magnet_set_dht(res, u);
			}
		}
		break;

	case MAGNET_KEY_G2:
		{
			int error;
			uint8 u;

			u = parse_uint8(value, NULL, 10, &error);
			if (!error) {
				magnet_set_g2(res, u);
			}
		}
		break;

	case MAGNET_KEY_NONE:
		g_message("unhandled parameter in MAGNET URI: \"%s\"", name);
		break;

	case NUM_MAGNET_KEYS:
		g_assert_not_reached();
	}

	G_FREE_NULL(to_free);
}

struct magnet_resource *
magnet_parse(const char *url, const char **error_str)
{
	static const struct magnet_resource zero_resource;
	struct magnet_resource res;
	const char *p, *next;

	res = zero_resource;
	clear_error_str(&error_str);

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
		const char *endptr;
		char name[16]; /* Large enough to hold longest key we know */

		name[0] = '\0';
		endptr = strchr(p, '=');
		if (endptr && p != endptr) {
			size_t name_len;

			name_len = endptr - p;
			g_assert(size_is_positive(name_len));

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
			g_message("skipping unknown key \"%s\" in MAGNET URI", name);
		} else {
			char *value;
			size_t value_len;

			value_len = endptr - p;
			value = h_strndup(p, value_len);

			plus_to_space(value);
			if (url_unescape(value, TRUE)) {
				magnet_handle_key(&res, name, value);
			} else {
				g_message("badly encoded value in MAGNET URI: \"%s\"", value);
			}
			HFREE_NULL(value);
		}

		while ('&' == endptr[0]) {
			endptr++;
		}
		next = endptr;
	}

	res.sources = pslist_reverse(res.sources);
	res.searches = pslist_reverse(res.searches);

	return wcopy(&res, sizeof res);
}

void
magnet_source_free(struct magnet_source **ms_ptr)
{
	struct magnet_source *ms = *ms_ptr;

	if (ms) {
		atom_str_free_null(&ms->hostname);
		atom_str_free_null(&ms->path);
		atom_str_free_null(&ms->url);
		atom_sha1_free_null(&ms->sha1);
		atom_tth_free_null(&ms->tth);
		atom_guid_free_null(&ms->guid);
		if (ms->proxies) {
			free_proxies_list(ms->proxies);
			ms->proxies = NULL;
		}
		wfree(ms, sizeof *ms);
		*ms_ptr = NULL;
	}
}

void
magnet_resource_free(struct magnet_resource **res_ptr)
{
	struct magnet_resource *res = *res_ptr;

	if (res) {
		pslist_t *sl;

		atom_str_free_null(&res->display_name);
		atom_sha1_free_null(&res->sha1);
		atom_tth_free_null(&res->tth);
		atom_str_free_null(&res->parq_id);
		atom_str_free_null(&res->guid);
		atom_str_free_null(&res->vendor);

		PSLIST_FOREACH(res->sources, sl) {
			struct magnet_source *ms = sl->data;
			magnet_source_free(&ms);
		}
		pslist_free_null(&res->sources);

		PSLIST_FOREACH(res->searches, sl) {
			const char *s = sl->data;
			atom_str_free_null(&s);
		}
		pslist_free_null(&res->searches);
		wfree(res, sizeof *res);
		*res_ptr = NULL;
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

static void
magnet_add_source(struct magnet_resource *res, struct magnet_source *s)
{
	g_return_if_fail(res);
	g_return_if_fail(s);

	res->sources = pslist_prepend(res->sources, s);
}

void
magnet_add_source_by_url(struct magnet_resource *res, const char *url)
{
	struct magnet_source *s;

	g_return_if_fail(res);
	g_return_if_fail(url);

	s = magnet_source_new();
	s->url = atom_str_get(url);
	magnet_add_source(res, s);
}

void
magnet_add_sha1_source(struct magnet_resource *res, const struct sha1 *sha1,
	const host_addr_t addr, const uint16 port, const struct guid *guid,
	const gnet_host_vec_t *proxies)
{
	struct magnet_source *s;

	g_return_if_fail(res);
	g_return_if_fail(sha1);
	g_return_if_fail(!res->sha1 || sha1_eq(res->sha1, sha1));
	g_return_if_fail(guid != NULL || port_is_valid(port));

	if (!res->sha1) {
		magnet_set_sha1(res, sha1);
	}

	s = magnet_source_new();
	s->addr = addr;
	s->port = port;
	s->sha1 = atom_sha1_get(sha1);
	s->guid = guid ? atom_guid_get(guid) : NULL;

	if (proxies != NULL) {
		int i, n;
		pslist_t *sl = NULL;

		n = gnet_host_vec_count(proxies);
		for (i = 0; i < n; i++) {
			gnet_host_t host;

			host = gnet_host_vec_get(proxies, i);
			sl = pslist_prepend(sl, gnet_host_dup(&host));
		}

		s->proxies = sl;
	}

	magnet_add_source(res, s);
}

void
magnet_add_search(struct magnet_resource *res, const char *search)
{
	g_return_if_fail(res);
	g_return_if_fail(search);

	res->searches = pslist_prepend(res->searches,
						deconstify_gchar(atom_str_get(search)));
}


void
magnet_set_sha1(struct magnet_resource *res, const struct sha1 *sha1)
{
	const struct sha1 *atom;

	g_return_if_fail(res);
	g_return_if_fail(sha1);

	atom = atom_sha1_get(sha1);
	atom_sha1_free_null(&res->sha1);
	res->sha1 = atom;
}

void
magnet_set_tth(struct magnet_resource *res, const struct tth *tth)
{
	const struct tth *atom;

	g_return_if_fail(res);
	g_return_if_fail(tth);

	atom = atom_tth_get(tth);
	atom_tth_free_null(&res->tth);
	res->tth = atom;
}


bool
magnet_set_exact_topic(struct magnet_resource *res, const char *topic)
{
	struct sha1 sha1;
	struct tth tth;

	if (urn_get_bitprint(topic, strlen(topic), &sha1, &tth)) {
		if (!res->sha1) {
			magnet_set_sha1(res, &sha1);
		}
		if (!res->tth) {
			magnet_set_tth(res, &tth);
		}
		return TRUE;
	} else if (urn_get_sha1(topic, &sha1)) {
		if (!res->sha1) {
			magnet_set_sha1(res, &sha1);
		}
		return TRUE;
	} else if (urn_get_tth(topic, strlen(topic), &tth)) {
		if (!res->tth) {
			magnet_set_tth(res, &tth);
		}
		return TRUE;
	} else {
		return FALSE;
	}
}

void
magnet_set_display_name(struct magnet_resource *res, const char *name)
{
	const char *atom;

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
magnet_append_item(str_t *s, bool escape_value,
	const char *key, const char *value)
{
	g_return_if_fail(s);
	g_return_if_fail(key);
	g_return_if_fail(value);

	if (0 == str_len(s)) {
		STR_CAT(s, "magnet:?");
	} else {
		str_putc(s, '&');
	}
	str_cat(s, key);
	str_putc(s, '=');

	if (escape_value) {
		char *escaped;

		escaped = url_escape_query(value);
		str_cat(s, escaped);
		if (escaped != value) {
			HFREE_NULL(escaped);
		}
	} else {
		str_cat(s, value);
	}
}

/**
 * @return A halloc()ed string.
 */
static char *
proxy_sequence_to_string(const sequence_t *s)
{
	str_t *str;

	str = str_new(0);

	if (!sequence_is_empty(s)) {
		sequence_iter_t *iter;

		iter = sequence_forward_iterator(s);
		while (sequence_iter_has_next(iter)) {
			gnet_host_t *host = sequence_iter_next(iter);
			str_putc(str, ':');
			str_cat(str, gnet_host_to_string(host));
		}
		sequence_iterator_release(&iter);
	}

	return str_s2c_null(&str);
}

/**
 * @return A halloc()ed string.
 */
static char *
proxies_to_string(pslist_t *proxies)
{
	sequence_t seq;

	return proxy_sequence_to_string(sequence_fill_from_pslist(&seq, proxies));
}

/**
 * Create the string representation of the push-proxies, for inclusion
 * in the push:// URL.
 *
 * @return An empty string (""), if the list is empty or the address NULL;
 * otherwise a colon-separated list of IP:port, beginning with a colon. The
 * string is newly allocated via halloc().
 */
char *
magnet_proxies_to_string(const sequence_t *proxies)
{
	if (NULL == proxies)
		return h_strdup("");

	return proxy_sequence_to_string(proxies);
}

/**
 * Convert magnet source to a string representation.
 *
 * @return A newly allocated string.
 */
char *
magnet_source_to_string(const struct magnet_source *s)
{
	char *url;

	g_return_val_if_fail(s, NULL);

	if (s->url) {
		url = g_strdup(s->url);
	} else {
		char *proxies = NULL;
		const char *host, *prefix;
		char prefix_buf[256];
		char port_buf[16];

		if (s->guid) {
			char guid_buf[GUID_HEX_SIZE + 1];

			guid_to_string_buf(s->guid, guid_buf, sizeof guid_buf);
			concat_strings(prefix_buf, sizeof prefix_buf,
				"push://", guid_buf, NULL_PTR);
			prefix = prefix_buf;
		} else {
			prefix = "http://";
		}

		port_buf[0] = '\0';
		if (s->hostname) {
			host = s->hostname;
			if (80 != s->port) {
				str_bprintf(port_buf, sizeof port_buf, ":%u",
					(unsigned) s->port);
			}
		} else if (s->guid) {
			proxies = proxies_to_string(s->proxies);
			host = proxies;
		} else {
			host = host_addr_port_to_string(s->addr, s->port);
		}
		if (s->path) {
			url = g_strconcat(prefix, host, port_buf, s->path, NULL_PTR);
		} else if (s->sha1) {
			url = g_strconcat(prefix, host, port_buf,
					"/uri-res/N2R?", bitprint_to_urn_string(s->sha1, s->tth),
					NULL_PTR);
		} else {
			url = g_strconcat(prefix, host, port_buf, "/", NULL_PTR);
		}

		HFREE_NULL(proxies);
	}

	return url;
}

/**
 * Create a string representation of the magnet resource.
 *
 * @return A newly allocated string via halloc().
 */
char *
magnet_to_string(const struct magnet_resource *res)
{
	pslist_t *sl;
	str_t *s;

	g_return_val_if_fail(res, NULL);

	s = str_new(0);

	if (res->display_name) {
		magnet_append_item(s, TRUE, "dn", res->display_name);
	}
	if (0 != res->size) {
		char buf[UINT64_DEC_BUFLEN];

		uint64_to_string_buf(res->size, buf, sizeof buf);
		magnet_append_item(s, FALSE, "xl", buf);
	}
	if (res->sha1) {
		magnet_append_item(s, FALSE, "xt",
			bitprint_to_urn_string(res->sha1, res->tth));
	}
	if (res->parq_id) {
		magnet_append_item(s, TRUE, "x.parq-id", res->parq_id);
	}
	if (res->vendor) {
		magnet_append_item(s, TRUE, "x.vndr", res->vendor);
	}
	if (res->guid) {
		magnet_append_item(s, TRUE, "x.guid", res->guid);
	}
	if (res->dht) {
		magnet_append_item(s, TRUE, "x.dht", "1");
	}
	if (res->g2) {
		magnet_append_item(s, TRUE, "x.g2", "1");
	}

	PSLIST_FOREACH(res->sources, sl) {
		char *url;

		url = magnet_source_to_string(sl->data);
		magnet_append_item(s, TRUE, "xs", url);
		G_FREE_NULL(url);
	}

	PSLIST_FOREACH(res->searches, sl) {
		magnet_append_item(s, TRUE, "kt", sl->data);
	}

	return str_s2c_null(&s);
}

/*
 * The following extensions are reserved for single-source magnets, such
 * as the ones used to persist the enqueued download sources.  There are
 * some useful meta-information about a given source that need to propagated
 * accross sessions.
 *
 * See the "FIXME" comment in download_store_magnets() to understand why
 * this is likely to be revised some day.
 *		--RAM, 2010-02-20
 */

/**
 * Record given string magnet resource at the supplied location.
 */
static void
magnet_resource_set_string(const char **p, const char *str)
{
	const char *atom;

	g_return_if_fail(p);
	g_return_if_fail(str);

	atom = atom_str_get(str);
	atom_str_free_null(p);
	*p = atom;
}

/**
 * This is a bit of a hack (an extension anyway) and should only be used
 * for magnets with a single logical source because the PARQ ID is only
 * valid for a certain source.
 */
void
magnet_set_parq_id(struct magnet_resource *res, const char *parq_id)
{
	g_return_if_fail(res);
	g_return_if_fail(parq_id);

	magnet_resource_set_string(&res->parq_id, parq_id);
}

/**
 * This is a bit of a hack (an extension anyway) and should only be used
 * for magnets with a single logical source because the vendor is only
 * valid for a certain source.
 */
void
magnet_set_vendor(struct magnet_resource *res, const char *vendor)
{
	g_return_if_fail(res);
	g_return_if_fail(vendor);

	magnet_resource_set_string(&res->vendor, vendor);
}

/**
 * This is a bit of a hack (an extension anyway) and should only be used
 * for magnets with a single logical source because the GUID is only
 * valid for a certain source.
 */
void
magnet_set_guid(struct magnet_resource *res, const char *guid)
{
	g_return_if_fail(res);
	g_return_if_fail(guid);

	magnet_resource_set_string(&res->guid, guid);
}

/**
 * This is a bit of a hack (an extension anyway) and should only be used
 * for magnets with a single logical source because DHT support is only
 * valid for a certain source.
 */
void
magnet_set_dht(struct magnet_resource *res, bool dht_support)
{
	g_return_if_fail(res);

	res->dht = booleanize(dht_support);
}

/**
 * This is a bit of a hack (an extension anyway) and should only be used
 * for magnets with a single logical source because G2 support is only
 * valid for a certain source.
 */
void
magnet_set_g2(struct magnet_resource *res, bool g2)
{
	g_return_if_fail(res);

	res->g2 = booleanize(g2);
}

/* vi: set ts=4 sw=4 cindent: */
