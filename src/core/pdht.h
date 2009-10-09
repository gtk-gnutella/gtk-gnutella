/*
 * $Id$
 *
 * Copyright (c) 2009, Raphael Manfredi
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
 * @ingroup core
 * @file
 *
 * Gnutella DHT "publish" interface.
 *
 * @author Raphael Manfredi
 * @date 2009
 */

#ifndef _core_pdht_h_
#define _core_pdht_h_

#include "share.h"		/* For shared_file_t */

/**
 * Publish error codes.
 */
typedef enum {
	PDHT_E_OK = 0,				/**< No error */
	PDHT_E_POPULAR,				/**< Value is popular, not fully published */
	PDHT_E_LOOKUP,				/**< Error during roots lookup */
	PDHT_E_LOOKUP_EXPIRED,		/**< Lookup expired */
	PDHT_E_SHA1,				/**< SHA1 of shared file is unavailable */
	PDHT_E_PENDING,				/**< Previous value publish still pending */
	PDHT_E_NOT_SHARED,			/**< File is no longer shared */
	PDHT_E_GGEP,				/**< Could not build GGEP DHT value */
	PDHT_E_NONE,				/**< Got no acknowledgement at all */
	PDHT_E_CANCELLED,			/**< Cancelled explicitly */
	PDHT_E_UDP_CLOGGED,			/**< UDP queue is clogged */
	PDHT_E_PUBLISH_EXPIRED,		/**< Publishing expired */
	PDHT_E_PUBLISH_ERROR,		/**< Other publishing error */

	PDHT_E_MAX					/**< Amount of error codes defined */
} pdht_error_t;

/**
 * Publish callback, invoked when the publishing request is finished, either
 * successfully or not.
 *
 * @param arg		user-supplied callback argument
 * @param code		status code of the operation
 * @param roots		number of roots to which the file was published
 */
typedef void (*pdht_cb_t)(gpointer arg, pdht_error_t code, unsigned roots);

/*
 * Public interface.
 */

void pdht_init(void);
void pdht_close(void);

void pdht_publish_file(shared_file_t *sf, pdht_cb_t cb, gpointer arg);
const char *pdht_strerror(pdht_error_t code);

#endif	/* _core_pdht_h_ */

/* vi: set ts=4 sw=4 cindent: */
