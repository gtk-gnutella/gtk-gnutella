
/* Filter search results */

#include "gnutella.h"

#include "search.h"
#include "filter.h"


gboolean filter_record(struct search *sch, struct record *rec)
{
	/* Check a particular record against the search filters and the global filters */
	/* Returns TRUE if the record can be displayed, FALSE if not */

	if (search_strict_and) { // config value for strict AND checking
		// XXX for now -- RAM
	}

	return TRUE;	/* XXX for now --RAM */
}

