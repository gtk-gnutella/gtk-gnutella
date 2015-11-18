/*
 * Copyright (c) 2015 Raphael Manfredi
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

/*
 * Source code for the "strtod" library procedure.
 *
 * Copyright (c) 1988-1993 The Regents of the University of California.
 * Copyright (c) 1994 Sun Microsystems, Inc.
 *
 * This software is copyrighted by the Regents of the University of
 * California, Sun Microsystems, Inc., Scriptics Corporation, ActiveState
 * Corporation and other parties.  The following terms apply to all files
 * associated with the software unless explicitly disclaimed in
 * individual files.
 *
 * The authors hereby grant permission to use, copy, modify, distribute,
 * and license this software and its documentation for any purpose, provided
 * that existing copyright notices are retained in all copies and that this
 * notice is included verbatim in any distributions. No written agreement,
 * license, or royalty fee is required for any of the authorized uses.
 * Modifications to this software may be copyrighted by their authors
 * and need not follow the licensing terms described here, provided that
 * the new terms are clearly indicated on the first page of each file where
 * they apply.
 *
 * IN NO EVENT SHALL THE AUTHORS OR DISTRIBUTORS BE LIABLE TO ANY PARTY
 * FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING OUT OF THE USE OF THIS SOFTWARE, ITS DOCUMENTATION, OR ANY
 * DERIVATIVES THEREOF, EVEN IF THE AUTHORS HAVE BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * THE AUTHORS AND DISTRIBUTORS SPECIFICALLY DISCLAIM ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.  THIS SOFTWARE
 * IS PROVIDED ON AN "AS IS" BASIS, AND THE AUTHORS AND DISTRIBUTORS HAVE
 * NO OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
 * MODIFICATIONS.
 *
 * GOVERNMENT USE: If you are acquiring this software on behalf of the
 * U.S. government, the Government shall have only "Restricted Rights"
 * in the software and related documentation as defined in the Federal
 * Acquisition Regulations (FARs) in Clause 52.227.19 (c) (2).  If you
 * are acquiring the software on behalf of the Department of Defense, the
 * software shall be classified as "Commercial Computer Software" and the
 * Government shall have only "Restricted Rights" as defined in Clause
 * 252.227-7013 (c) (1) of DFARs.  Notwithstanding the foregoing, the
 * authors grant the U.S. Government and others acting in its behalf
 * permission to use and distribute the software in accordance with the
 * terms specified in this license.
 *
 * RCS: @(#) $Id: strtod.c,v 1.1.1.4 2003/03/06 00:09:04 landonf Exp $
 *
 * Adaptation to gtk-gnutella standards, including renamings, reformatting
 * tightening of the pre-conditions, etc.. were done by Raphael Manfredi.
 */

#include "common.h"

#include "parse_double.h"

#include "ascii.h"

#include "override.h"			/* Must be the last header included */

/**
 * Largest possible base 10 exponent.  Any exponent larger than this will
 * already produce underflow or overflow, so there's no need to worry about
 * additional digits.
 */
#define PARSE_DBL_MAX_EXPONENT	511

/**
 * Table giving binary powers of 10.  Entry i is 10^(2^i).
 *
 * It is used to convert decimal exponents into floating-point numbers.
 */
static double powers_of_10[] = {
    10.,
    100.,
    1.0e4,
    1.0e8,
    1.0e16,
    1.0e32,
    1.0e64,
    1.0e128,
    1.0e256
};

/*
 * Parse a floating-point number in ASCII decimal representation into a double.
 *
 * The representation must have form "-I.FE-X", where I is the integer part
 * of the mantissa, F is the fractional part of the mantissa, and X is the
 * exponent.
 *
 * Either of the signs may be "+", "-", or omitted.  Either I or F may be
 * omitted, noth both.  The decimal point isn't necessary unless F is present.
 * The "E" may actually be an "e".  E and X may both be omitted, but X must
 * be present if E is present.
 *
 * @param src		the string to parse.
 * @param endptr	if non-NULL, set to address of first invalid character
 * @param errorptr	indicates a parse error if not zero.
 *
 * EINVAL means there was no parseable number.
 * ERANGE means the number would not fit the representation.
 *
 * @return
 *    The parsed value or 0.0 in case of an error. If 0.0 is returned,
 *    the error must be checked to determine whether there was an error
 *    or whether the parsed value was indeed 0.0.
 */
double
parse_double(const char *src, char const **endptr, int *errorptr)
{
	int sign, exp_sign = FALSE;
	double fraction, dbl_exp, *d;
	register const char *p;
	register int c;
	int frac_exp = 0;
	int exp = 0;		/* Exponent read from "EX" field */
	int mant_size;		/* Number of digits in mantissa */
	int dec_pt;			/* Number of mantissa digits BEFORE decimal point */
	const char *p_exp;	/* Temporarily holds location of exponent in string */

	g_assert(src != NULL);
	g_assert(errorptr != NULL);

	/*
	 * Strip off leading blanks and check for a sign.
	 */

	p = src;

	if ('-' == *p) {
		sign = TRUE;
		p++;
	} else {
		if ('+' == *p)
			p++;
		sign = FALSE;
	}

	/*
	 * Count the number of digits in the mantissa (including the decimal
	 * point), and also locate the decimal point.
	 */

	dec_pt = -1;
	for (mant_size = 0, c = *p; c != 0; mant_size++, c = *++p) {
		if (!is_ascii_digit(c)) {
			if (c != '.' || dec_pt >= 0)
				break;
			dec_pt = mant_size;
		}
	}

	/*
	 * What is frac_exp?
	 *
	 * It is the exponent that derives from the fractional part.  Under
	 * normal circumstatnces, it is the negative of the number of digits
	 * in F.  However, if I is very long, the last digits of I get dropped
	 * (otherwise a long I with a large negative exponent could cause an
	 * unnecessary overflow on I alone).  In this case, frac_exp is
	 * incremented one for each dropped digit.
	 */

	p_exp = p;				/* Where we expect the exponent to start */
	if (dec_pt < 0) {
		dec_pt = mant_size;
	} else {
		mant_size--;		/* One of the digits was the point. */
	}

	/*
	 * There must be at least one digit in the mantissa.
	 */

	if (0 == mant_size) {
		*errorptr = EINVAL;
		p = src;
		fraction = 0.0;
		goto done;
	}

	p -= mant_size;

	if (mant_size > 18) {
		frac_exp = dec_pt - 18;
		mant_size = 18;
	} else {
		frac_exp = dec_pt - mant_size;
	}

	/*
	 * Now suck up the digits in the mantissa.  Use two integers to
	 * collect 9 digits each (this is faster than using floating-point).
	 * If the mantissa has more than 18 digits, ignore the extras, since
	 * they can't affect the value anyway.
	 */

	{
		int frac1 = 0, frac2 = 0;

		/*
		 * We have alredy validated earlier that all the characters covering
		 * the mantissa are either digits or the decimal point, and there can
		 * be just one decimal point.
		 */

		for ( ; mant_size > 9; mant_size--) {
			c = *p++;
			if ('.' == c)
				c = *p++;
			frac1 = 10 * frac1 + (c - '0');
		}
		for (; mant_size > 0; mant_size--) {
			c = *p++;
			if ('.' == c)
				c = *p++;
			frac2 = 10 * frac2 + (c - '0');
		}
		fraction = (1.0e9 * frac1) + frac2;
	}

	/*
	 * Skim off the exponent.
	 */

	p = p_exp;
	c = *p;
	if ('E' == c || 'e' == c) {
		c = *p++;
		if ('-' == c) {
			exp_sign = TRUE;
			p++;
		} else {
			if ('+' == c)
				p++;
			exp_sign = FALSE;
		}
		if (!is_ascii_digit(*p)) {
			p = p_exp; 	/* We're not facing an exponent, stop before 'e' */
		} else {
			while (is_ascii_digit(*p)) {
				exp = exp * 10 + (*p - '0');
				p++;
			}
		}
	}
	if (exp_sign) {
		exp = frac_exp - exp;
	} else {
		exp = frac_exp + exp;
	}

	/*
	 * Generate a floating-point number that represents the exponent.
	 *
	 * Do this by processing the exponent one bit at a time to combine
	 * many powers of 2 of 10.
	 *
	 * Then combine the exponent with the fraction.
	 */

	if (exp < 0) {
		exp_sign = TRUE;
		exp = -exp;
	} else {
		exp_sign = FALSE;
	}
	if (exp > PARSE_DBL_MAX_EXPONENT) {
		*errorptr = ERANGE;
		fraction = 0.0;
		goto done;
	}
	for (dbl_exp = 1.0, d = powers_of_10; exp != 0; exp >>= 1, d++) {
		if (exp & 01) {
			dbl_exp *= *d;
		}
	}
	if (exp_sign) {
		fraction /= dbl_exp;
	} else {
		fraction *= dbl_exp;
	}

	*errorptr = 0;		/* Parsing was successful */

	/* FALL THROUGH */

done:
	if (endptr != NULL)
		*endptr = p;

	if (sign)
		return -fraction;
	return fraction;
}

