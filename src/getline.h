/*
 * $Id$
 *
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

#ifndef __getline_h__
#define __getline_h__

#include <glib.h>

#define MAX_LINE_SIZE	2048	/* Maximum length for any line */

/*
 * getline() return codes.
 */

#define READ_MORE		0		/* OK, expecting more */
#define READ_DONE		1		/* OK, got whole line */
#define READ_OVERFLOW	2		/* Reached max line size */

/*
 * A getline "object".
 *
 * Note that we don't use MAX_LINE_SIZE for ease of implementation.
 * Given the high encapsulation of the processing, it would not be a
 * problem.  Rather, it is a design choice: we could be fed a very long
 * line, practically endless, and we would be stuck reading and reading.
 * A limit must be drawn.
 */

typedef struct getline {
	guchar line[MAX_LINE_SIZE];		/* Accumulator, NUL terminated when done */
	guint pos;						/* Next writing position in line[] */
} getline_t;

/*
 * Public interface.
 */

getline_t *getline_make(void);
void getline_free(getline_t *o);
void getline_reset(getline_t *o);
gint getline_read(getline_t *o, guchar *data, gint len, gint *used);
guchar *getline_str(getline_t *o);
gint getline_length(getline_t *o);
void getline_copy(getline_t *source, getline_t *dest);

#endif	/* __getline_h__ */

/* vi: set ts=4: */

