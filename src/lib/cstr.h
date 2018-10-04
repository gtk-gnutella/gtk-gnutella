/*
 * Copyright (c) 2018 Raphael Manfredi
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
 * Miscellaneous utilities for C strings.
 *
 * @author Raphael Manfredi
 * @date 2018
 */

#ifndef _cstr_h_
#define _cstr_h_

#include "common.h"

/*
 * Public interface.
 */

/*
 * Clones of strlcpy() with a different signature and behaviour:
 *
 * We wish to have the destination and length parameters following eachother
 * so that we can use constructs like ARYLEN() when possible, to factorize the
 * variable name.
 *
 * The variants are provided for convenience:
 *
 * cstr_lcpy() is an emulation of strlcpy(), with just a different signature.
 *
 * cstr_bcpy() behaves like cstr_lcpy() but will loudly warn if its destination
 * buffer is too small.
 *
 * cstr_fcpy() simply returns a boolean indicating whether the string fitted, in
 * order to, again, avoid having to spell out the buffer variable name in a test
 * of the returned value simply to check wether the result is greater than the
 * supplied buffer.
 *
 * The letters before the "cpy" in the name can be remembered with the following
 * indications:
 *
 * 'b' stands for block/batch.  Usually, it means the returned value will not be
 * used to check whether the buffer was large enough and will be ignored.
 *
 * 'f' stands for fits, because the routine returns TRUE when the string fitted
 * completely within the destination buffer.
 *
 * 'l' stands for length, probably.  This is the same letter as strlcpy().
 */

size_t cstr_bcpy(char *dst, size_t len, const char *src);
bool cstr_fcpy(char *dst, size_t len, const char *src);
size_t cstr_lcpy(char *dst, size_t len, const char *src);

#endif /* _cstr_h_ */

/* vi: set ts=4 sw=4 cindent: */
