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
 * @author Christian Biere
 * @date 2006
 */

#ifndef _magnet_h_
#define _magnet_h_

#include "common.h"

#include "lib/gnet_host.h"
#include "lib/host_addr.h"
#include "lib/misc.h"
#include "lib/pslist.h"
#include "lib/sequence.h"

struct magnet_source {
	const char *url;			/* string atom */
	const char *hostname;		/* string atom */
	const char *path;			/* string atom */
	const struct sha1 *sha1;	/* SHA1 atom */
	const struct tth *tth;		/* TTH atom */
	const struct guid *guid;	/* GUID atom */
	pslist_t *proxies;	/* List of walloc()ed (gnet_host_t *) */
	host_addr_t addr;
	uint16 port;
};

struct magnet_resource {
	const char *display_name;	/* string atom */
	const struct sha1 *sha1;	/* SHA1 atom */
	const struct tth *tth;		/* TTH atom */
	const char *parq_id;		/* string atom */
	const char *vendor;			/* string atom */
	const char *guid;			/* string atom */
	pslist_t *sources;		/* List of walloc()ed (struct magnet_source *) */
	pslist_t *searches;		/* List of string atoms */
	filesize_t size;
	unsigned dht:1;				/* DHT support for this source */
	unsigned g2:1;				/* G2 support for this source */
};

struct magnet_resource *magnet_parse(const char *url, const char **error_str);
struct magnet_source *magnet_parse_exact_source(const char *uri,
							const char **error_str);
void magnet_source_free(struct magnet_source **ms_ptr);
void magnet_resource_free(struct magnet_resource **res_ptr);

struct magnet_resource *magnet_resource_new(void);
struct magnet_source *magnet_source_new(void);
char *magnet_to_string(const struct magnet_resource *res);
char *magnet_source_to_string(const struct magnet_source *s);
void magnet_set_filesize(struct magnet_resource *res, filesize_t size);
void magnet_set_display_name(struct magnet_resource *res, const char *name);
bool magnet_set_exact_topic(struct magnet_resource *res,
			const char *topic);
void magnet_set_sha1(struct magnet_resource *res, const struct sha1 *sha1);
void magnet_set_tth(struct magnet_resource *res, const struct tth *tth);
void magnet_add_search(struct magnet_resource *res, const char *search);
void magnet_add_source_by_url(struct magnet_resource *res, const char *url);
void magnet_add_sha1_source(struct magnet_resource *res,
		const struct sha1 *sha1, const host_addr_t addr, const uint16 port,
		const struct guid *guid, const gnet_host_vec_t *proxies);

/* Extensions */
void magnet_set_parq_id(struct magnet_resource *res, const char *parq_id);
void magnet_set_guid(struct magnet_resource *res, const char *guid);
void magnet_set_dht(struct magnet_resource *res, bool dht_support);
void magnet_set_g2(struct magnet_resource *res, bool g2);
void magnet_set_vendor(struct magnet_resource *res, const char *vendor);
char *magnet_proxies_to_string(const sequence_t *proxies);

#endif /* _magnet_h_ */
/* vi: set ts=4 sw=4 cindent: */
