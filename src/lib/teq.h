/*
 * Copyright (c) 2013, Raphael Manfredi
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
 * Thread Event Queue.
 *
 * @author Raphael Manfredi
 * @date 2013
 */

#ifndef _teq_h_
#define _teq_h_

/**
 * Type of acknowledgments that can be requested for an event.
 */
typedef enum {
	TEQ_AM_CALL,		/**< Direct routine call from foreign thread */
	TEQ_AM_EVENT,		/**< Send back an event to the posting thread */
	TEQ_AM_CALLOUT		/**< Register event into the main callout queue */
} teq_ackmode_t;

/**
 * An RPC routine for teq_rpc().
 */
typedef void *(*teq_rpc_fn_t)(void *arg);

/*
 * Public interface.
 */

bool teq_is_supported(unsigned id);
size_t teq_count(unsigned id);
void teq_create(void);
void teq_io_create(void);
void teq_create_if_none(void);
void teq_post(unsigned id, notify_fn_t routine, void *data);
void teq_post_ack(unsigned id, notify_fn_t routine, void *data,
	teq_ackmode_t mode, notify_fn_t ack, void *ack_data);
void *teq_rpc(unsigned id, teq_rpc_fn_t routine, void *data);
void *teq_safe_rpc(unsigned id, teq_rpc_fn_t routine, void *data);
void teq_wait(predicate_fn_t predicate, void *arg);
size_t teq_dispatch(void);
void teq_set_throttle(int process, int delay);

#endif /* _teq_h_ */

/* vi: set ts=4 sw=4 cindent: */
