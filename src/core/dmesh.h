/*
 * Copyright (c) 2002-2009, Raphael Manfredi
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

/**
 * @ingroup core
 * @file
 *
 * Download mesh.
 *
 * @author Raphael Manfredi
 * @date 2002-2009
 */

#ifndef _core_dmesh_h_
#define _core_dmesh_h_

#include "common.h"
#include "downloads.h"
#include "hcache.h"			/* For host_net_t */

#include "if/gen/dmesh_url.h"

#include "lib/hashlist.h"
#include "lib/gnet_host.h"

/**
 * Our level of support for firewalled alt-locs.
 */
#define FWALT_VERSION_MAJOR 0
#define FWALT_VERSION_MINOR 1

/**
 * A download mesh info (describes an URL) for a non-firewalled servent.
 *
 * It can describe URLs like:
 *
 *  - http://1.2.3.4:5678/get/1/name.txt
 *  - http://1.2.3.4:5678/uri-res/N2R?urn:sha1:ABCDEFGHIJKLMNOPQRSTUVWXYZ234567
 *
 * We use the `idx' to discriminate between the two forms, URN_INDEX meaning
 * it's an URN.
 */
typedef struct {
	const char *name;			/**< File name (atom) */
	host_addr_t addr;			/**< Host address */
	uint idx;					/**< File index (URN_INDEX means URN access) */
	uint16 port;				/**< Host port */
} dmesh_urlinfo_t;

/**
 * A download mesh info for a firewalled servent.
 */
typedef struct {
	const guid_t *guid;			/**< Servent's GUID (atom) */
	hash_list_t *proxies;		/**< Known push proxies (gnet_host_t) */
} dmesh_fwinfo_t;

/**
 * Error codes from dmesh_url_parse().
 */
extern dmesh_url_error_t dmesh_url_errno;

/*
 * Public interface
 */

void dmesh_init(void);
void dmesh_close(void);

bool dmesh_can_use_fwalt(void);

const char *dmesh_url_strerror(dmesh_url_error_t errnum);
bool dmesh_url_parse(const char *url, dmesh_urlinfo_t *info);

bool dmesh_add(
	const struct sha1 *sha1, const host_addr_t addr, uint16 port, uint idx,
	const char *name, time_t stamp);

bool dmesh_remove(
	const struct sha1 *sha1, const host_addr_t addr, uint16 port, uint idx,
	const char *name);

void dmesh_add_alternate(const struct sha1 *sha1,
		host_addr_t addr, uint16 port);
void dmesh_add_good_alternate(const struct sha1 *sha1,
		host_addr_t addr, uint16 port);
void dmesh_remove_alternate(const struct sha1 *sha1,
		host_addr_t addr, uint16 port);
void dmesh_add_alternates(const struct sha1 *sha1, const gnet_host_vec_t *vec);

void dmesh_add_good_firewalled(const struct sha1 *sha1,
	const struct guid *guid);

void dmesh_negative_alt(const struct sha1 *sha1,
	host_addr_t reporter, host_addr_t addr, uint16 port);
void dmesh_good_mark(const struct sha1 *sha1,
	host_addr_t addr, uint16 port, bool good);

int dmesh_count(const struct sha1 *sha1);

bool dmesh_collect_sha1(const char *value, struct sha1 *sha1);
void dmesh_collect_locations(const struct sha1 *sha1, const char *value,
	const gnet_host_t *origin, const char *user_agent);
void dmesh_collect_compact_locations(const struct sha1 *sha1,
		const char *value, const gnet_host_t *origin, const char *user_agent);
void dmesh_collect_fw_hosts(const struct sha1 *sha1, const char *value,
	const gnet_host_t *origin, const char *user_agent);
void dmesh_collect_negative_locations(const struct sha1 *sha1,
	const char *value, host_addr_t reporter, const char *user_agent);
int dmesh_fill_alternate(const struct sha1 *sha1,
		gnet_host_t *hvec, int hcnt);

int dmesh_alternate_location(
	const struct sha1 *sha1, char * buf, size_t size, const host_addr_t addr,
	time_t last_sent, const char *vendor, fileinfo_t *fi,
	bool request, const struct guid *guid, host_net_t net);

void dmesh_multiple_downloads(
	const struct sha1 *sha1, filesize_t size, fileinfo_t *fi);

void dmesh_check_results_set(gnet_results_set_t *rs);

void dmesh_store(void);
void dmesh_ban_store(void);

#endif	/* _core_dmesh_h_ */

/* vi: set ts=4 sw=4 cindent: */
