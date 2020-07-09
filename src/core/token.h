/*
 * Copyright (c) 2003, Raphael Manfredi
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
 * Token management.
 *
 * @author Raphael Manfredi
 * @date 2003
 */

#ifndef _core_token_h_
#define _core_token_h_

#include "common.h"
#include "lib/host_addr.h"

#define TOKEN_VERSION_SIZE	(4 + 3 + 20)	/**< stamp + seed + SHA1 */
#define TOKEN_START_DATE	1045868400		/**< When we started using tokens */

/**
 * Error codes for token validation.
 */
typedef enum {
	TOK_OK = 0,					/**< OK */
	TOK_BAD_LENGTH,				/**< Bad length */
	TOK_BAD_STAMP,				/**< Bad timestamp */
	TOK_BAD_INDEX,				/**< Bad key index */
	TOK_INVALID,				/**< Invalid */
	TOK_BAD_ENCODING,			/**< Not base64-encoded */
	TOK_BAD_KEYS,				/**< Keys not found */
	TOK_BAD_VERSION,			/**< Bad version string */
	TOK_OLD_VERSION,			/**< Version older than expected */
	TOK_BAD_LEVEL_ENCODING,		/**< Level not base64-encoded */
	TOK_BAD_LEVEL_LENGTH,		/**< Bad level length */
	TOK_SHORT_LEVEL,			/**< Level too short */
	TOK_INVALID_LEVEL,			/**< Level mismatch */
	TOK_MISSING_LEVEL,			/**< Missing level */

	TOK_MAX_ERROR
} tok_error_t;

/*
 * Public interface.
 */

const char *tok_strerror(tok_error_t errnum);
char *tok_version(void);
char *tok_short_version(void);
tok_error_t tok_version_valid(
	const char *version, const char *tokenb64, int len, host_addr_t addr);
bool tok_is_ancient(time_t now);

#endif	/* _core_token_h_ */

/* vi: set ts=4 sw=4 cindent: */
