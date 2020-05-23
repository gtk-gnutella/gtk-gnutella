/*
 * Copyright (c) 2011, Raphael Manfredi
 *
 * Interface definition file.  One of the files that defines structures,
 * macros, etc. as part of the gui/core interface.
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

#ifndef _if_core_mq_h_
#define _if_core_mq_h_

/**
 * Queue fullness status summary.
 */
typedef enum mq_status {
	MQ_S_EMPTY,				/**< Queue is empty */
	MQ_S_DELAY,				/**< Queue not empty, but below lowat */
	MQ_S_WARNZONE,			/**< Queue between hiwat and lowat, no FC */
	MQ_S_FLOWC,				/**< Queue in flow control, dropping some traffic */
	MQ_S_SWIFT				/**< Queue in swift mode, dropping more traffic */
} mq_status_t;

#endif /* _if_core_mq_h_ */

/* vi: set ts=4 sw=4 cindent: */
