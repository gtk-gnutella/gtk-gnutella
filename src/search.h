
#ifndef __search_h__
#define __search_h__

#include <time.h>

struct results_set
{
	guchar guid[16];
	guint32 num_recs;
	guint32 ip;
	guint16 port;
	guint16 status;			/* Parsed status bits from trailer */
	guint32 speed;
	guint32 trailer_len;	/* Length of the trailer data */
	gchar *trailer;			/* Raw trailer data */

	GSList *records;
};

/*
 * Flags for the `status' field above.
 */

#define ST_KNOWN_VENDOR		0x80
#define ST_UPLOADED			0x04
#define ST_BUSY				0x02
#define ST_FIREWALL			0x01

struct record
{
	struct results_set *results_set;
	gchar *name;			/* File name */
	guint32 size;			/* Size of file, in bytes */
	guint32 index;			/* Index for GET command */
	gchar *tag;				/* Optional tag data, NUL terminated */
};


extern GSList *searches;							/* List of search structs */

/* flags for _new_search() */
#define SEARCH_PASSIVE     0x01         /* start a passive search */

#endif	/* __search_h__ */

/* vi: set ts=3: */

