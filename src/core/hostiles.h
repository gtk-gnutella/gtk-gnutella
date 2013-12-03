/*
 * Copyright (c) 2003, Markus Goetz & Raphael Manfredi
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
 * Support for the hostiles.txt of BearShare.
 *
 * @author Markus Goetz
 * @author Raphael Manfredi
 * @date 2003
 */

#ifndef _core_hostiles_h_
#define _core_hostiles_h_

#include "common.h"
#include "lib/host_addr.h"

/**
 * Reasons why a host could be banned.
 */
typedef enum hostiles_flags {
	HSTL_CLEAN				= 0,			/**< Not hostile */
	HSTL_STATIC				= (1 << 0),		/**< In static list */
	HSTL_DUMB				= (1 << 1),		/**< Dumb spammer */
	HSTL_WEIRD_MSG			= (1 << 2),		/**< Sends weird messages */
	HSTL_DUP_INDEX			= (1 << 3),		/**< Duplicate index in results */
	HSTL_DUP_SHA1			= (1 << 4),		/**< Duplicate SHA1 in results */
	HSTL_FAKE_SPAM			= (1 << 5),		/**< Sends fake query hits */
	HSTL_NAME_SPAM			= (1 << 6),		/**< Sends names flagged as spam */
	HSTL_URL_SPAM			= (1 << 7),		/**< Sends URL-based spam */
	HSTL_URN_SPAM			= (1 << 8),		/**< Sends URN flagged as spam */
	HSTL_EVIL_FILENAME		= (1 << 9),		/**< Sends evil filenames */
	HSTL_BAD_UTF8			= (1 << 10),	/**< Sends invalid UTF-8 */
	HSTL_OOB				= (1 << 11),	/**< Sends unrequested OOB hits */
	HSTL_UDP_GUESS			= (1 << 12),	/**< UDP-relayed hit, not GUESS */
	HSTL_BAD_FILE_INDEX		= (1 << 13),	/**< Bad file index in hits */
	HSTL_GTKG				= (1 << 14),	/**< Hit advertised from GTKG */
	HSTL_NO_GTKG_VERSION	= (1 << 15),	/**< Hit advertised from GTKG */
	HSTL_BAD_GTKG_GUID		= (1 << 16),	/**< GTKG hit with improper GUID */
	HSTL_MANY_ALT_LOCS		= (1 << 17),	/**< Too many alt-locs in hits */
	HSTL_EVIL_TIMESTAMP		= (1 << 18),	/**< Evil timestamp in hits */
	HSTL_NO_WHATS_NEW		= (1 << 19),	/**< Missing what's new support */
	HSTL_CLOSE_FILENAME		= (1 << 20),	/**< Filename similar to query */
	HSTL_MISSING_XML		= (1 << 21),	/**< Missing XML in hit */
	HSTL_NO_CREATE_TIME		= (1 << 22),	/**< Missing "CT" in hits */
	HSTL_ODD_GUID			= (1 << 23),	/**< Odd GUID in hits */
	HSTL_BANNED_GUID		= (1 << 24),	/**< Banned GUID in hits */
	HSTL_BAD_VENDOR_CODE	= (1 << 25),	/**< Bad vendor code in hits */
} hostiles_flags_t;

const char *hostiles_flags_to_string(const hostiles_flags_t flags);

void hostiles_init(void);
void hostiles_close(void);

hostiles_flags_t hostiles_check(const host_addr_t addr);
bool hostiles_spam_check(const host_addr_t addr, uint16 port);

void hostiles_dynamic_add(const host_addr_t addr, const char *reason,
	hostiles_flags_t flags);
void hostiles_spam_add(const host_addr_t addr, uint16 port);

static inline bool
hostiles_is_known(const host_addr_t addr)
{
	return HSTL_CLEAN != hostiles_check(addr);
}

#endif /* _core_hostiles_h_ */

/* vi: set ts=4 sw=4 cindent: */
