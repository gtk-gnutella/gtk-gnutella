/*
 * Copyright (c) 2002, Raphael Manfredi
 *
 * PDU Messages.
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

#ifndef __pmsg_h__
#define __pmsg_h__

#include <glib.h>

/*
 * A data buffer, can be shared by several message blocks.
 *
 * There are two incarnations of a message data block: one where the buffer's
 * arena is contiguous to the header and starts at its end (the header
 * structure has been stolen at the head of the physical data block), and one
 * where the buffer's arena was independently allocated.
 *
 * The free routine, when present, only frees the data part of the data buffer.
 * Naturally, in its embedded form, this is the whole buffer.  The first
 * argument to the free routine is the start of the data to free, i.e. it will
 * be the pdata structure in the embedded case, or the arena base in the
 * detached form.
 *
 * The d_embedded[] field is our reliable discriminent: since it is part of
 * the structure, it is necessarily within that structure.  Therefore, when
 * d_arena points to it, we know that the data buffer is of the "embedded"
 * kind.
 */

typedef void (*pdata_free_t)(gpointer p, gpointer arg);

typedef struct pdata {
	pdata_free_t d_free;			/* Free routine */
	gpointer d_arg;					/* Argument to free routine */
	gint d_refcnt;					/* Reference count */
	gchar *d_arena;					/* First byte in buffer */
	gchar *d_end;					/* First byte after buffer */
	gchar d_embedded[1];			/* Start of embedded arena */
} pdata_t;

#define pdata_start(x)		((x)->d_arena)
#define pdata_len(x)		((x)->d_end - (x)->d_arena)
#define pdata_addref(x)		do { (x)->d_refcnt++; } while (0)

/*
 * A message block
 */

typedef struct pmsg {
	gchar *m_rptr;					/* First unread byte in buffer */
	gchar *m_wptr;					/* First unwritten byte in buffer */
	pdata_t *m_data;				/* Data buffer */
	gint m_prio;					/* Message priority (0 = normal) */
} pmsg_t;

#define pmsg_start(x)		((x)->m_data->d_arena)
#define pmsg_phys_len(x)	pdata_len((x)->m_data)
#define pmsg_is_writable(x)	((x)->m_data->d_refcnt == 1)
#define pmsg_prio(x)		((x)->m_prio)

#define pmsg_is_unread(x)	((x)->m_rptr == (x)->m_data->d_arena)
#define pmsg_read_base(x)	((x)->m_rptr)

/*
 * Message priorities.
 */

#define PMSG_P_DATA		0			/* Regular data, lowest priority */
#define PMSG_P_CONTROL	1			/* Control message */
#define PMSG_P_URGENT	2			/* Urgent message */
#define PMSG_P_HIGHEST	3			/* Highest priority */

/*
 * Public interface
 */

gint pmsg_size(pmsg_t *mb);
pmsg_t *pmsg_new(gint prio, void *buf, gint len);
pmsg_t *pmsg_alloc(gint prio, pdata_t *db, gint roff, gint woff);
pmsg_t *pmsg_clone(pmsg_t *mb);
void pmsg_free(pmsg_t *mb);
gint pmsg_write(pmsg_t *mb, gpointer data, gint len);
gint pmsg_read(pmsg_t *mb, gpointer data, gint len);

pdata_t *pdata_new(gint len);
pdata_t *pdata_allocb(void *buf, gint len,
	pdata_free_t freecb, gpointer freearg);
pdata_t *pdata_allocb_ext(void *buf, gint len,
	pdata_free_t freecb, gpointer freearg);
void pdata_free_nop(gpointer p, gpointer arg);
void pdata_unref(pdata_t *db);

#endif	/* __pmsg_h__ */

/* vi: set ts=4: */
