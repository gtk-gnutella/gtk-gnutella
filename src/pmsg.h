/*
 * Copyright (c) 2002, Raphael Manfredi
 *
 * PDU Messages.
 */

#ifndef __pmsg_h__
#define __pmsg_h__

#include <glib.h>

/*
 * A data buffer, can be shared by several message blocks.
 */

typedef void (*pdata_free_t)(gpointer p, gint arg);

typedef struct pdata {
	pdata_free_t d_free;			/* Free routine */
	gint d_arg;						/* Argument to free routine */
	gint d_refcnt;					/* Reference count */
	gchar *d_end;					/* First byte after buffer */
	gchar d_arena[1];				/* Start of buffer's arena */
} pdata_t;

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

pdata_t *pdata_new(gint len);
pdata_t *pdata_allocb(void *buf, gint len, pdata_free_t freecb, gint freearg);
void pdata_unref(pdata_t *db);

#endif	/* __pmsg_h__ */

/* vi: set ts=4: */
