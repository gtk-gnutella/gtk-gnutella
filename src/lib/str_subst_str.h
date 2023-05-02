/*
 * Copyright (c) 2023 Raphael Manfredi
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * String substitution using string patterns.
 *
 * @author Raphael Manfredi
 * @date 2023
 */

#ifndef _str_subst_str_h_
#define _str_subst_str_h_

#include "common.h"

#include "str.h"

/*
 * Public interface.
 */

size_t str_subst_first_str(str_t *s, const char *needle, const char *rep);
size_t str_subst_all_str(str_t *s, const char *needle, const char *rep);
size_t str_case_subst_first_str(str_t *s, const char *needle, const char *rep);
size_t str_case_subst_all_str(str_t *s, const char *needle, const char *rep);

#endif /* _str_subst_str_h_ */

/* vi: set ts=4 sw=4 cindent: */
