/*
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
 * Country limits.
 *
 * @author Raphael Manfredi
 * @date 2009
 */

#ifndef _core_ctl_h_
#define _core_ctl_h_

#include "lib/host_addr.h"

/*
 * Limit definitions.
 */

enum ctld {
	CTL_D_INCOMING	= (1 << 0),		/**< Incoming HTTP */
	CTL_D_OUTGOING	= (1 << 1),		/**< Outgoing HTTP */
	CTL_D_GNUTELLA	= (1 << 2),		/**< Gnutella connections */
	CTL_D_BROWSE	= (1 << 3),		/**< Browse-host requests */
	CTL_D_UDP		= (1 << 4),		/**< Incoming UDP (excluding DHT) */
	CTL_D_QUERY		= (1 << 5),		/**< Gnutella queries */
	CTL_D_STEALTH	= (1 << 6),		/**< Stealth mode */
	CTL_D_NORMAL	= (1 << 7),		/**< Normalized feedback */
	CTL_D_MESH		= (1 << 8),		/**< Download mesh */
	CTL_D_CACHE		= (1 << 9),		/**< Valid/fresh host caches */
	CTL_D_WHITELIST	= (1 << 10),	/**< Whitelist overrides */
	CTL_D_QHITS		= (1 << 11),	/**< Replies */
	CTL_D_MAX
};

/*
 * Useful flag shortcuts
 */

#define CTL_S_ANY_TCP	(CTL_D_INCOMING|CTL_D_GNUTELLA|CTL_D_BROWSE)

/*
 * Public interface.
 */

void ctl_init(void);
void ctl_close(void);
void ctl_parse(const char *s);
bool ctl_limit(const host_addr_t ha, unsigned flags);

#endif /* _core_ctl_h_ */

/* vi: set ts=4 sw=4 cindent: */
