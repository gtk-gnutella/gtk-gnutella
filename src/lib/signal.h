/*
 * $Id$
 *
 * Copyright (c) 2011, Raphael Manfredi
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
 * Signal dispatching support.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#ifndef _signal_h_
#define _signal_h_

/*
 * Public interface.
 */

typedef void (*signal_handler_t)(int signo);
signal_handler_t signal_set(int signo, signal_handler_t handler);
const char *signal_name(int signo);
gboolean signal_in_handler(void);

gboolean signal_enter_critical(sigset_t *oset);
gboolean signal_leave_critical(const sigset_t *oset);

#endif /* _signal_h_ */

/* vi: set ts=4 sw=4 cindent:  */
