/*
 * $Id$
 *
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Gnutella Generic Extension Protocol (GGEP).
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

#ifndef __ggep_h__
#define __ggep_h__

#include <glib.h>

/*
 * GGEP Extension Header Flags.
 */

#define GGEP_F_LAST		0x80		/* Last extension in GGEP block */
#define GGEP_F_COBS		0x40		/* Whether COBS was used on payload */
#define GGEP_F_DEFLATE	0x20		/* Whether payload was deflated */
#define GGEP_F_MBZ		0x10		/* Bits that Must Be Zero */
#define GGEP_F_IDLEN	0x0f		/* Where ID length is stored */

/*
 * GGEP Length Encoding.
 */

#define GGEP_L_CONT		0x80		/* Continuation present */
#define GGEP_L_LAST		0x40		/* Last byte */
#define GGEP_L_VALUE	0x3f		/* Value */

#define GGEP_L_XFLAGS	(GGEP_L_CONT | GGEP_L_LAST)

/*
 * Public interaface.
 */

#endif	/* __ggep_h__ */

/* vi: set ts=4: */

