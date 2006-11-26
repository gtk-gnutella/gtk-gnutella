/*
 * $Id$
 *
 * Copyright (c) 2002, Vidar Madsen
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

/**
 * @ingroup lib
 * @file
 *
 * Functions to compute likelihood of two file names being the same file.
 *
 * @author Vidar Madsen
 * @date 2002
 */

#ifndef _fuzzy_h_
#define _fuzzy_h_

#include "common.h"

/**
 * FUZZY_SHIFT is used to shift the real score to gain extra precision
 * in favour of using float
 */
#define FUZZY_SHIFT 10

gulong fuzzy_compare(const char *str1, const char *str2);

#endif /* _fuzzy_h_ */

