/*
 * Copyright (c) 2002-2003, Raphael Manfredi
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
 * Callout queue.
 *
 * @author Raphael Manfredi
 * @date 2001-2003
 */

#ifndef _cq_h_
#define _cq_h_

#include "common.h"

typedef struct cqueue cqueue_t;
typedef struct cevent cevent_t;
typedef struct cperiodic cperiodic_t;
typedef struct cidle cidle_t;

/**
 * A callout queue event callback.
 *
 * @param cq		the queue which fired the event
 * @param udata		user-supplied callback data
 */
typedef void (*cq_service_t)(struct cqueue *cq, void *udata);

/**
 * A periodic event callback.
 *
 * @param udata		user-supplied callback data
 *
 * @return whether the perdioc event should continue to be called.
 */
typedef bool (*cq_invoke_t)(void *udata);

typedef uint64 cq_time_t;		/**< Virtual time for callout queue */

enum cq_info_magic { CQ_INFO_MAGIC = 0x12c867d4 };

/**
 * Callout queue information that can be retrieved.
 */
typedef struct {
	enum cq_info_magic magic;
	const char *name;			/**< Queue name (atom) */
	const char *parent;			/**< Parent queue name (atom), NULL if none */
	uint stid;					/**< Scheduling thread ID */
	size_t periodic_count;		/**< Amount of periodic events */
	size_t idle_count;			/**< Amount of idle events */
	size_t event_count;			/**< Amount of registered events */
	size_t heartbeat_count;		/**< Amount of heartbeats */
	size_t triggered_count;		/**< Amount of triggered events */
	int period;					/**< Period, in ms */
	time_t last_idle;			/**< Last idle scheduling */
} cq_info_t;

static inline void
cq_info_check(const cq_info_t * const cqi)
{
	g_assert(cqi != NULL);
	g_assert(CQ_INFO_MAGIC == cqi->magic);
}

/*
 * Interface routines.
 */

double cq_main_coverage(int old_ticks);

void cq_init(cq_invoke_t idle, const uint32 *debug);
void cq_main_dispatch(void);
void cq_halt(void);
void cq_close(void);

cqueue_t *cq_main(void);
cqueue_t *cq_make(const char *name, cq_time_t now, int period);
cqueue_t *cq_submake(const char *name, cqueue_t *parent, int period);
cqueue_t *cq_main_submake(const char *name, int period);
void cq_free_null(cqueue_t **cq_ptr);
cevent_t *cq_insert(cqueue_t *cq, int delay, cq_service_t fn, void *arg);
cevent_t *cq_main_insert(int delay, cq_service_t fn, void *arg);
cq_time_t cq_remaining(const cevent_t *ev);
size_t cq_heartbeat(cqueue_t *cq);
bool cq_expire(cevent_t *ev);
void cq_zero(cqueue_t *cq, cevent_t **ev_ptr);
void cq_acknowledge(cqueue_t *cq, cevent_t *ev);
void cq_event(cqueue_t *cq);
bool cq_cancel(cevent_t **handle_ptr);
bool cq_replace(cevent_t *ev, cq_service_t fn, void *arg);
bool cq_resched(cevent_t *handle, int delay);
int cq_ticks(const cqueue_t *cq);
int cq_count(const cqueue_t *cq);
int cq_delay(const cqueue_t *cq);
const char *cq_name(const cqueue_t *cq);
size_t cq_idle(cqueue_t *cq);
size_t cq_main_idle(void);
unsigned cq_main_thread_id(void);

cperiodic_t *cq_periodic_add(cqueue_t *cq,
	int period, cq_invoke_t event, void *arg);
cperiodic_t *cq_periodic_main_add(int period, cq_invoke_t event, void *arg);
void cq_periodic_resched(cperiodic_t *cp, int period);
void cq_periodic_remove(cperiodic_t **cp_ptr);
cidle_t *cq_idle_add(cqueue_t *cq, cq_invoke_t event, void *arg);
void cq_idle_remove(cidle_t **ci_ptr);

const char *cq_time_to_string(cq_time_t t);

struct pslist *cq_info_list(void);
void cq_info_list_free_null(struct pslist **sl_ptr);

#endif	/* _cq_h_ */

/* vi: set ts=4 sw=4 cindent: */
