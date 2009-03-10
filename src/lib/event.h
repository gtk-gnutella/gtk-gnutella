/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Richard Eckart
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

#ifndef _event_h_
#define _event_h_

#include "common.h"

#include "tm.h"

typedef enum frequency_type {
    FREQ_SECS,
    FREQ_UPDATES
} frequency_t;

struct subscriber {
    GCallback           cb;
    enum frequency_type f_type;
    guint32             f_interval;
    time_t              last_call;
};

typedef struct event {
    const char *name;
    guint32      triggered_count;
    GSList      *subscribers;
} event_t;

struct event *event_new(const char *name);

#define event_destroy(evt) G_STMT_START {                          \
    real_event_destroy(evt);                                       \
    G_FREE_NULL(evt);                                              \
} G_STMT_END

void real_event_destroy(struct event *evt);

void event_add_subscriber(
    struct event *evt, GCallback cb, frequency_t t, guint32 interval);
void event_remove_subscriber(struct event *evt, GCallback cb);

guint event_subscriber_count(struct event *evt);
gboolean event_subscriber_active(struct event *evt);

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
		GSList *sl;											 			 	\
		event_t *evt;										   				\
		struct subscriber *s;												\
		time_t now;									   					 	\
		gboolean t;															\
	} vars_;																\
																			\
	vars_.evt = (ev);														\
	vars_.now = (time_t) -1;												\
	vars_.sl = vars_.evt->subscribers;										\
	for (/* NOTHING */; vars_.sl; vars_.sl = g_slist_next(vars_.sl)) {		\
		vars_.s = vars_.sl->data;											\
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
						(guint32) delta_time(vars_.now, vars_.s->last_call);\
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
} G_STMT_END

struct event_table {
    GHashTable *events;
};

struct event_table *event_table_new(void);

#define event_table_destroy(t) G_STMT_START {                      \
    real_event_table_destroy(t);                                   \
    G_FREE_NULL(t);                                                \
} G_STMT_END
void real_event_table_destroy(struct event_table *t, gboolean cleanup);


void event_table_add_event(struct event_table *t, struct event *evt);
void event_table_remove_event(struct event_table *t, struct event *evt);
void event_table_remove_all(struct event_table *t);

#endif	/* _event_h_ */

/* vi: set ts=4 sw=4 cindent: */
