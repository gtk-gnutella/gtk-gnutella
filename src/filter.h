/*
 * Copyright (c) 2001-2002, Raphael Manfredi
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

#ifndef __filter_h__
#define __filter_h__

#include <regex.h>

#include "matching.h"

enum filter_type {
  FILTER_TEXT,
  FILTER_IP,
  FILTER_SIZE
};

enum filter_text_type {
  FILTER_PREFIX,
  FILTER_WORDS,
  FILTER_SUFFIX,
  FILTER_SUBSTR,
  FILTER_REGEXP
};

struct filter {
  enum filter_type type;	/* type of filter, see above */
  int positive:1;		/* true: display matches; false: hide matches */
  union {
    struct _f_text {
      int case_sensitive:1;	/* case sensitive (true) or not (false) */
      enum filter_text_type type; /* type of match, see above */
      union {
	char *match;		/* match string */
	cpattern_t *pattern;	/* substring pattern */
	GList *words;		/* a list of substring patterns */
	regex_t *re;		/* regular expression match */
      } u;
    } text;
    struct _f_ip {
      guint32 addr;		/* IP address */
      guint32 mask;		/* netmask */
    } ip;
    struct _f_size {
      size_t lower;		/* lower limit or 0 */
      size_t upper;		/* upper limit or ~0 */
    } size;
  } u;
};

extern GList *global_filters;

/* ---- Functions ---- */

void filters_init(void);
void filters_open_dialog(void);

gboolean filter_record(struct search *, struct record *);

#endif							/* __filter_h__ */

/* vi: set ts=4: */
