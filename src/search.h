
#ifndef __search_h__
#define __search_h__

#include <time.h>

struct results_set
{
	guchar guid[16];
	guint32 num_recs;
	guint32 ip;
	guint16 port;
	guint32 speed;

	GSList *records;
};

struct record
{
	struct results_set *results_set;
	gchar *name;
	guint32 size;
	guint32 index;
};


extern GSList *searches;							/* List of search structs */

/* flags for _new_search() */
#define SEARCH_PASSIVE     0x01         /* start a passive search */

#endif	/* __search_h__ */

/* vi: set ts=3: */

