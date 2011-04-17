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
 * Wait queue -- fires callback when waiting event is released.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#ifndef _wq_h_
#define _wq_h_

struct wq_event;
typedef struct wq_event wq_event_t;

/**
 * Status that can be returned by wait queue callbacks.
 */
typedef enum {
	WQ_REMOVE,			/**< Remove from wait queue */
	WQ_SLEEP,			/**< Leave in queue */
	WQ_EXCLUSIVE,		/**< Got exclusive resource, don't wakeup others */
} wq_status_t;

/**
 * Wait queue callback, invoked when wakeup event was received.
 *
 * The sleep_data is a user-supplied parameter given to wq_sleep() when the
 * callback was registered.
 *
 * The wakeup_data is whatever data was passed to wq_wakeup().  It is supposed
 * to be understood by all the waiting parties on the given key.
 *
 * @param sleep_data		user-supplied data at sleep time
 * @param wakeup_data		waking-up data
 */
typedef wq_status_t (*wq_callback_t)(void *sleep_data, void *wakeup_data);

/*
 * Public interface.
 */

void wq_init(void);
void wq_close(void);

wq_event_t *wq_sleep(const void *key, wq_callback_t cb, void *arg);
void wq_wakeup(const void *key, void *data);
void wq_cancel(wq_event_t **we_ptr);

#endif /* _wq_h_ */

/* vi: set ts=4 sw=4 cindent: */
