/*
 * Copyright (c) 2001-2002, Raphael Manfredi
 *
 * Filter search results.
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

#include "gnutella.h"

#include "search.h"
#include "filter.h"
#include "matching.h"
#include "misc.h"

GList *global_filters = NULL;

/* returns 0 for hide, 1 for display, -1 for undecided */
static int apply_filters(GList *list, struct record *rec)
{
#define FIRE	{ g_free(l_name); return f->positive ? 1 : 0; }
	size_t namelen;
	char *l_name;
	namelen = strlen(rec->name);
	l_name = g_malloc(sizeof(char) * (namelen + 1));
	strlower(l_name, rec->name);
	list = g_list_first(list);
	while (list) {
		size_t n;
		int i;
		struct filter *f; 
		f = (struct filter *)list->data;
		switch (f->type) {
		case FILTER_TEXT:
			switch (f->u.text.type) {
			case FILTER_PREFIX:
				if (strncmp(f->u.text.case_sensitive ?
					    rec->name : l_name,
					    f->u.text.u.match,
					    strlen(f->u.text.u.match)) == 0)
					FIRE;
				break;
			case FILTER_WORDS: {
				GList *l;
				for (l = g_list_first(f->u.text.u.words);
				     l; l = g_list_next(l))
					if (pattern_qsearch
					    ((cpattern_t *)l->data,
					     f->u.text.case_sensitive
					     ? rec->name : l_name, 0, 0, qs_any)
					    != NULL)
						FIRE;
				}
				break;
			case FILTER_SUFFIX:
				n = strlen(f->u.text.u.match);
				if (namelen > n
				    && strcmp((f->u.text.case_sensitive
					       ? rec->name : l_name) + namelen
					      - n, f->u.text.u.match) == 0)
					FIRE;
				break;
			case FILTER_SUBSTR: 
				if (pattern_qsearch(f->u.text.u.pattern,
						    f->u.text.case_sensitive
						    ? rec->name : l_name, 0, 0,
						    qs_any) != NULL)
					FIRE;
				break;
			case FILTER_REGEXP:
				if ((i = regexec(f->u.text.u.re, rec->name,
						 0, NULL, 0)) == 0)
					FIRE;
				if (i == REG_ESPACE)
					g_warning("regexp memory overflow");
				break;
			default:
				g_error("text filter type %d unknown",
					f->u.text.type);
			}
			break;
		case FILTER_IP:
			if ((rec->results_set->ip & f->u.ip.mask) == f->u.ip.addr)
				FIRE;
			break;
		case FILTER_SIZE:
			if (rec->size >= f->u.size.lower
			 && rec->size <= f->u.size.upper)
				FIRE;
			break;
		default:
			g_error("filter type %d unknown", f->type);
			break;
		}
		list = g_list_next(list);
	}
	g_free(l_name);
	return -1;
}

gboolean filter_record(struct search *sch, struct record *rec)
{
	/*
	 * Check a particular record against the search filters and the global
	 * filters
	 *
	 * Returns TRUE if the record can be displayed, FALSE if not
	 */
	int r;

	if (search_strict_and) {	// config value for strict AND checking
		// XXX for now -- RAM
	}

	if (sch->filters && (r = apply_filters(sch->filters, rec)) != -1)
		return r;

	if (global_filters)
		return apply_filters(global_filters, rec); /* -1 means display here */

	return -1;			/* TRUE => display (not filtered) */
}

