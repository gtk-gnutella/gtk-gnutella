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
 * String substitution and matching using regular expressions.
 *
 * @author Raphael Manfredi
 * @date 2023
 */

#ifndef _str_subst_re_h_
#define _str_subst_re_h_

#include "common.h"

#include "str.h"

struct re_match;		/* No dependency with "re.h" here */
struct re_regex;
typedef struct str_match str_match_t;

/*
 * Public interface.
 */

bool str_match_re_plain(const str_t *s, const char *pat, struct re_match *pos);
bool str_case_match_re_plain(const str_t *s, const char *pat, struct re_match *pos);
bool str_match_re_plain_offset(const str_t *s,
	ssize_t off, const char *pat, struct re_match *pos);
bool str_case_match_re_plain_offset(const str_t *s,
	ssize_t off, const char *pat, struct re_match *pos);

bool str_match_re(const str_t *s,
	const char *pat, const char *opt, struct re_match *pos, size_t npos);
bool str_match_re_full(const str_t *s, ssize_t offset,
	const char *pat, const char *opt, struct re_match *pos, size_t npos);

bool str_match_rec(const str_t *s,
	const struct re_regex *re, const char *opt, struct re_match *pos, size_t npos);

bool str_match_rec_full(const str_t *s, ssize_t offset,
	const struct re_regex *re, const char *opt, struct re_match *pos, size_t npos);

str_match_t *str_match_re_keep(const str_t *s, const char *pat, const char *opt);
str_match_t *str_match_re_keep_offset(
	const str_t *s, ssize_t off, const char *pat, const char *opt);

str_match_t *str_match_rec_keep(
	const str_t *s, const struct re_regex *re, const char *opt);
str_match_t *str_match_rec_keep_offset(
	const str_t *s, ssize_t off, const struct re_regex *re, const char *opt);

str_t *str_new_from_match(const str_match_t *m, size_t idx);
str_t *str_new_using_match(const str_match_t *m, const char *expr);
str_t *str_new_before_match(const str_match_t *m);
str_t *str_new_at_match(const str_match_t *m);
str_t *str_new_after_match(const str_match_t *m);

void str_match_free(str_match_t *m);
void str_match_free_null(str_match_t **m_ptr);

size_t str_subst_re_plain(str_t *s, const char *p, const char *r, const char *opt);
size_t str_subst_re(str_t *s, const char *p, const char *r, const char *opt);

size_t str_subst_rec_plain(str_t *s,
	const struct re_regex *re, const char *r, const char *opt);
size_t str_subst_rec(str_t *s,
	const struct re_regex *re, const char *r, const char *opt);

#endif /* _str_subst_re_h_ */

/* vi: set ts=4 sw=4 cindent: */
