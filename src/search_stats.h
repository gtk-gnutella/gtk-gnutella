#ifndef _search_stats_h_
#define _search_stats_h_

#include <glib.h>

#include "matching.h"

void enable_search_stats();
void reset_search_stats();
void tally_search_stats(const word_vec_t *);

#endif
