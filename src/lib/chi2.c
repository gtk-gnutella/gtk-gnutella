/*
 * Copyright (c) 2012, Raphael Manfredi
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
 * Chi-squared statistics.
 *
 * This is based on a public implementation of the Chi-squared distribution
 * by Jacob Wells (released July 31st 2012), which was adapted for inclusion
 * in this library.
 *
 * Reference material:
 *
 * http://en.wikipedia.org/wiki/Regularized_Gamma_function
 * http://en.wikipedia.org/wiki/Chi-squared_distribution
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#include "common.h"

#ifdef I_MATH
#include <math.h>
#endif	/* I_MATH */

#include "chi2.h"

static double
KM(double s, double z)
{
	double sum = 1.0, num = 1.0, denom = 1.0;
	int i;

	/* Make the power series converge */

	for (i = 0; i < 200; i++) {
		num *= z;
		denom *= ++s;
		sum += (num / denom);
	}

	return sum;
}

/**
 * Computes the lower Incomplete Gamma Function.
 *
 * The computation is slow because it involves a power series that needs to
 * be developped sufficiently to ensure convergence.
 */
static double
lower_igf(double s, double z)
{
	double c;

	if (z < 0.0)
		return 0.0;

	c = 1.0 / s;
	c *= pow(z, s) * exp(-z);

	return c * KM(s, z);
}

/**
 * Approximates the Gamma function with Stirling's formula.
 */
static double
approx_gf(double z)
{
	const double INV_E = 0.36787944117144232;	/* 1.0 / e */
	const double TWO_PI = 6.2831853071795865;	/* 2.0 * PI */
	const double INV_Z = 1.0 / z;
	double d;

 	/*
	 * gf(z) ~ sqrt(2*PI/z) * (1/e * (z + (1 / (12z - 1/10z))))^z
	 */

	d = 0.1 * INV_Z;
	d = 1.0 / ((12 * z) - d);
	d = (d + z) * INV_E;
	d = pow(d, z);
	d *= sqrt(TWO_PI * INV_Z);

	return d;
}

/**
 * Computes the value of the chi-squared cumulative distribution (one-tail).
 *
 * When conducting a chi-squared fitness test, the critical value is the sum of
 * (Oi - Ei)^2 / Ei, where Oi is the set of observed frequencies and Ei the set
 * of expected frequencies.
 *
 * @param freedom		degrees of freedom
 * @param critical		critical value for chi-squared test
 *
 * @return the one-tail cumulative distribution of the chi-squared probability
 * density function, from the critical value up to infinity.
 */
double
chi2_upper_tail(int freedom, double critical)
{
	double k, x;

	if G_UNLIKELY(critical < 0.0 || freedom < 1)
		return 0.0;

	if (2 == freedom)
		return exp(-0.5 * critical);

	x = critical * 0.5;
	k = freedom * 0.5;

	return 1.0 - lower_igf(k, x) / approx_gf(k);
}

/* vi: set ts=4 sw=4 cindent: */
