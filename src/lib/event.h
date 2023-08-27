/*
 * Copyright (c) 2002-2003, Richard Eckart
 * Copyright (c) 2013 Raphael Manfredi
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
 * @ingroup lib
 * @file
 *
 * Event mangement & dispatching logic.
 *
 * @author Richard Eckart
 * @date 2002-2003
 * @author Raphael Manfredi
 * @date 2013
 */

#ifndef _event_h_
#define _event_h_

#include "common.h"

#include "pslist.h"
#include "mutex.h"
#include "tm.h"

typedef enum frequency_type {
    FREQ_SECS,
    FREQ_UPDATES
} frequency_t;

enum subscriber_magic { SUBSCRIBER_MAGIC = 0x2184e261 };

struct subscriber {
	enum subscriber_magic magic;
    enum frequency_type f_type;
    uint32 f_interval;
    time_t last_call;
    callback_fn_t cb;
};

static inline void
subscriber_check(const struct subscriber * const s)
{
	g_assert(s != NULL);
	g_assert(SUBSCRIBER_MAGIC == s->magic);
}

enum event_magic { EVENT_MAGIC = 0x6a7563c2 };

typedef struct event {
	enum event_magic magic;
    uint32 triggered_count;
    const char *name;
    pslist_t *subscribers;
	mutex_t lock;
} event_t;

static inline void
event_check(const struct event * const evt)
{
	g_assert(evt != NULL);
	g_assert(EVENT_MAGIC == evt->magic);
}

event_t *event_new(const char *name);

void event_destroy(event_t *evt);
void event_add_subscriber(
    event_t *evt, callback_fn_t cb, frequency_t t, uint32 interval);
void event_remove_subscriber(event_t *evt, callback_fn_t cb);

size_t event_subscriber_count(const event_t *evt);
bool event_subscriber_active(const event_t *evt);

/*
 * T_VETO:   breaks trigger chain as soon as a subscriber returns
 *           a value != 0.
 *
 * T_NORMAL: will call all subscribers in the chain. Use for
 *           callbacks with a void return type.
 */
#define T_VETO(sig, params)	if (((sig) vars_.s->cb) params ) break;
#define T_NORMAL(sig, params)	((sig) vars_.s->cb) params ;

#define event_trigger(ev, callback) G_STMT_START {				  		 	\
	struct {																\
		pslist_t *sl;										 			 	\
		event_t *evt;										   				\
		struct subscriber *s;												\
		time_t now;									   					 	\
		bool t;																\
	} vars_;																\
																			\
	event_check(ev);														\
	mutex_lock(&(ev)->lock);												\
	vars_.evt = (ev);														\
	vars_.now = (time_t) -1;												\
	vars_.sl = vars_.evt->subscribers;										\
	for (/* NOTHING */; vars_.sl; vars_.sl = pslist_next(vars_.sl)) {		\
		vars_.s = vars_.sl->data;											\
		subscriber_check(vars_.s);											\
		vars_.t = 0 == vars_.s->f_interval;									\
		if (!vars_.t) {														\
			switch (vars_.s->f_type) {							 			\
			case FREQ_UPDATES:									 			\
				vars_.t = 0 == (vars_.evt->triggered_count %				\
									vars_.s->f_interval);					\
				break;											 			\
			case FREQ_SECS:													\
				if ((time_t) -1 == vars_.now)								\
					vars_.now = tm_time();									\
				vars_.t = vars_.s->f_interval <=							\
						(uint32) delta_time(vars_.now, vars_.s->last_call); \
				break;														\
			default:														\
				g_assert_not_reached();										\
			}													  			\
		}																	\
		if (vars_.t) {														\
			if (FREQ_SECS == vars_.s->f_type) {								\
				if ((time_t) -1 == vars_.now)								\
					vars_.now = tm_time();									\
				vars_.s->last_call = vars_.now;								\
			}																\
			callback														\
		}																	\
	}																		\
	vars_.evt->triggered_count++;											\
	mutex_unlock(&(ev)->lock);												\
} G_STMT_END

#endif	/* _event_h_ */

/* vi: set ts=4 sw=4 cindent: */
