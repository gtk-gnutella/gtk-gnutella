/*
 * Copyright (c) 2008, Raphael Manfredi
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
 * @ingroup dht
 * @file
 *
 * Kademlia publishing.
 *
 * @author Raphael Manfredi
 * @date 2009
 */

#ifndef _if_dht_publish_h_
#define _if_dht_publish_h_

#include "value.h"
#include "lookup.h"

/**
 * Publish error codes.
 */
typedef enum {
	PUBLISH_E_OK = 0,			/**< No error */
	PUBLISH_E_CANCELLED,		/**< Publish cancelled by user */
	PUBLISH_E_UDP_CLOGGED,		/**< Outgoing UDP traffic clogged */
	PUBLISH_E_EXPIRED,			/**< Publish expired */
	PUBLISH_E_POPULAR,			/**< Published value is popular */
	PUBLISH_E_ERROR,			/**< Getting STORE reply errors */
	PUBLISH_E_NONE,				/**< No acknowledgement received */

	PUBLISH_E_MAX				/**< Amount of error codes defined */
} publish_error_t;


typedef struct publish publish_t;

/**
 * The information structure supplied to the value publishing callback.
 */
typedef struct publish_info {
	const lookup_rs_t *rs;		/**< The set of STORE roots used */
	const uint16 *status;		/**< Array of STORE status per node in path */
	unsigned published;			/**< # of nodes where publishing was done */
	unsigned candidates;		/**< # of nodes where STORE was possible */
} publish_info_t;

/**
 * Value publishing callback.
 *
 * @param arg			user-supplied callback argument
 * @param code			status code for publish operation
 * @param info			publishing information
 */
typedef void (*publish_cb_t)(void *arg,
	publish_error_t code, const publish_info_t *info);

/*
 * Public interface.
 */

const char *publish_strerror(publish_error_t error);
void publish_cancel(publish_t *pb, bool callback);

publish_t *publish_value(dht_value_t *value, const lookup_rs_t *rs,
	publish_cb_t cb, void *arg);
publish_t *publish_value_background(dht_value_t *value,
	const lookup_rs_t *rs, const uint16 *status,
	publish_cb_t cb, void *arg);

#endif	/* _if_dht_publish_h_ */

/* vi: set ts=4 sw=4 cindent: */
