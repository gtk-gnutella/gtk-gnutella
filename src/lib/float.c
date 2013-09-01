/*
 * Copyright (c) 1996, Robert G. Burger
 * Copyright (c) 2011, Raphael Manfredi
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
 * Copyright (c) 1996 Robert G. Burger. Permission is hereby granted,
 * free of charge, to any person obtaining a copy of this software, to deal
 * in the software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the software.
 *
 * The software is provided "as is," without warranty of any kind, express or
 * implied, including but not limited to the warranties of merchantability,
 * fitness for a particular purpose and noninfringement. In no event shall
 * the author be liable for any claim, damages or other liability, whether
 * in an action of contract, tort or otherwise, arising from, out of or in
 * connection with the software or the use or other dealings in the software.
 *
 * Links:
 *
 * http://www.cs.indiana.edu/~burger/FP-Printing-PLDI96.pdf
 * http://www.cs.indiana.edu/~burger/fp/
 *
 * Adaptation to gtk-gnutella standards done by Raphael Manfredi.
 */

/**
 * @ingroup lib
 * @file
 *
 * Floating point formatting.
 *
 * @author Raphael Manfredi
 * @date 2011
 * @author Robert G. Burger
 * @date 1996
 */

#include "common.h"
#include "float.h"
#include "mutex.h"
#include "unsigned.h"

#include "override.h"			/* Must be the last header included */

#if 0
#define FLOAT_DEBUG
#endif
#if 0
#define FLOAT_SAFETY			/* Enable safety assertions */
#endif

#ifdef FLOAT_SAFETY
#define safety_assert(x)			g_assert(x)
#define safety_assert_log(x, ...)	g_assert_log(x, __VA_ARGS__)
#else
#define safety_assert(x)
#define safety_assert_log(x, ...)
#endif

/* exponent stored + 1024, hidden bit to left of decimal point */
#define bias 1023
#define bitstoright 52
#define m1mask 0xf
#define hidden_bit 0x100000

#define BIGSIZE 24
#define MIN_E -1074
#define MAX_FIVE 325
#define B_P1 ((uint64) 1 << 52)

typedef struct {
   int l;
   uint64 d[BIGSIZE];
} bignum_t;

/*
 * The original code uses global static variables for formatting, but this
 * is not acceptable in gtk-gnutella given that we want to be able to safely
 * format floating-point numbers from within a signal handler, possibly
 * interrupting a previously running floating point formatting.
 *
 * To avoid changing too much code and putting a big context on the stack, we
 * keep the context static but have a set of context elements indexed by a
 * global recursion variable.
 *		--RAM, 2011-11-06
 */

#define FLOAT_RECURSION	3	/**< Maximum recursion levels allowed */

static struct float_context {
	bignum_t c_R, c_S, c_MM;
	bignum_t c_S2, c_S3, c_S4, c_S5, c_S6, c_S7, c_S8, c_S9;
	int c_s_n, c_qr_shift;
	/* For float_dragon() */
	bignum_t c_MP;
} float_context[FLOAT_RECURSION];

static bignum_t five[MAX_FIVE];
static int recursion_level = -1;
static bool float_inited;
static mutex_t float_lock = MUTEX_INIT;

#define THREAD_FUNNEL		mutex_lock_hidden(&float_lock)
#define THREAD_UNFUNNEL		mutex_unlock_hidden(&float_lock)

#define R			float_context[recursion_level].c_R
#define S			float_context[recursion_level].c_S
#define MM			float_context[recursion_level].c_MM
#define S2			float_context[recursion_level].c_S2
#define S3			float_context[recursion_level].c_S3
#define S4			float_context[recursion_level].c_S4
#define S5			float_context[recursion_level].c_S5
#define S6			float_context[recursion_level].c_S6
#define S7			float_context[recursion_level].c_S7
#define S8			float_context[recursion_level].c_S8
#define S9			float_context[recursion_level].c_S9
#define s_n			float_context[recursion_level].c_s_n
#define qr_shift	float_context[recursion_level].c_qr_shift
#define MP			float_context[recursion_level].c_MP

#define ADD(x, y, z, k) {\
	uint64 x_add, z_add;\
	x_add = (x);\
	if ((k))\
		z_add = x_add + (y) + 1, (k) = (z_add <= x_add);\
	else\
		z_add = x_add + (y), (k) = (z_add < x_add);\
	(z) = z_add;\
}

#define SUB(x, y, z, b) {\
	uint64 x_sub, y_sub;\
	x_sub = (x); y_sub = (y);\
	if ((b))\
		(z) = x_sub - y_sub - 1, b = (y_sub >= x_sub);\
	else\
		(z) = x_sub - y_sub, b = (y_sub > x_sub);\
}

#define MUL(x, y, z, k) {\
	uint64 x_mul, low, high;\
	x_mul = (x);\
	low = (x_mul & 0xffffffff) * (y) + (k);\
	high = (x_mul >> 32) * (y) + (low >> 32);\
	(k) = high >> 32;\
	(z) = (low & 0xffffffff) | (high << 32);\
}

#define SLL(x, y, z, k) {\
	uint64 x_sll = (x);\
	(z) = (x_sll << (y)) | (k);\
	(k) = x_sll >> (64 - (y));\
}

#ifdef FLOAT_DEBUG
static void
print_big(bignum_t *x)
{
	int i;
	uint64 *p;

	printf("#x");
	i = x->l;
	safety_assert(i < BIGSIZE);
	p = &x->d[i];
	for (p = &x->d[i]; i >= 0; i--) {
		uint64 b = *p--;
		printf("%08x%08x", (int)(b >> 32), (int)(b & 0xffffffff));
	}
}
#endif	/* FLOAT_DEBUG */

static void
mul10(bignum_t *x)
{
	int i, l;
	uint64 *p, k;

	safety_assert(x->l < BIGSIZE);
	safety_assert(x->l >= 0);

	l = x->l;
	for (i = l, p = &x->d[0], k = 0; i >= 0; i--)
		MUL(*p, 10, *p++, k);

	safety_assert(p - &x->d[0] == 1 + x->l);

	if (k != 0)
		*p = k, x->l = l+1;

	safety_assert(x->l < BIGSIZE);
}

static void
big_short_mul(bignum_t *x, uint64 y, bignum_t *z)
{
	int i, xl, zl;
	uint64 *xp, *zp, k;
	uint32 high, low;

	safety_assert(x->l < BIGSIZE);
	safety_assert(x->l >= 0);

	xl = x->l;
	xp = &x->d[0];
	zl = xl;
	zp = &z->d[0];
	high = y >> 32;
	low = y & 0xffffffff;
	for (i = xl, k = 0; i >= 0; i--, xp++, zp++) {
		uint64 xlow, xhigh, z0, t, c, z1;
		xlow = *xp & 0xffffffff;
		xhigh = *xp >> 32;
		z0 = (xlow * low) + k; /* Cout is (z0 < k) */
		t = xhigh * low;
		z1 = (xlow * high) + t;
		c = (z1 < t);
		t = z0 >> 32;
		z1 += t;
		c += (z1 < t);
		*zp = (z1 << 32) | (z0 & 0xffffffff);
		k = (xhigh * high) + (c << 32) + (z1 >> 32) + (z0 < k);
	}

	safety_assert(zp - &z->d[0] == 1 + zl);

	if (k != 0)
		*zp = k, zl++;
	z->l = zl;

	safety_assert(z->l < BIGSIZE);
	safety_assert(z->l >= 0);
}

static int
estimate(int n)
{
	if (n < 0)
		return (int)(n*0.3010299956639812);
	else
		return 1+(int)(n*0.3010299956639811);
}

static void
one_shift_left(int y, bignum_t *z)
{
	int n, m, i;
	uint64 *zp;

	n = y / 64;
	m = y % 64;
	safety_assert(n < BIGSIZE);
	zp = &z->d[0];
	for (i = n; i > 0; i--)
		*zp++ = 0;
	*zp = (uint64)1 << m;
	z->l = n;

	safety_assert(z->l >= 0);
	safety_assert(zp - &z->d[0] == z->l);
}

static void
short_shift_left(uint64 x, int y, bignum_t *z)
{
	int n, m, i, zl;
	uint64 *zp;

	n = y / 64;
	m = y % 64;
	safety_assert(n < BIGSIZE);
	zl = n;
	zp = &z->d[0];
	for (i = n; i > 0; i--)
		*zp++ = 0;
	if (m == 0) {
		*zp = x;
	} else {
		uint64 high = x >> (64 - m);
		*zp = x << m;
		if (high != 0)
			*++zp = high, zl++;
	}
	z->l = zl;
	safety_assert(z->l < BIGSIZE);
	safety_assert(z->l >= 0);
	safety_assert(zp - &z->d[0] == z->l);
}

static void
big_shift_left(bignum_t *x, int y, bignum_t *z)
{
	int n, m, i, xl, zl;
	uint64 *xp, *zp, k;

	n = y / 64;
	m = y % 64;
	safety_assert(n < BIGSIZE);
	xl = x->l;
	xp = &x->d[0];
	zl = xl + n;
	zp = &z->d[0];
	for (i = n; i > 0; i--)
		*zp++ = 0;
	if (m == 0) {
		for (i = xl; i >= 0; i--)
			*zp++ = *xp++;
	} else {
		for (i = xl, k = 0; i >= 0; i--)
			SLL(*xp++, m, *zp++, k);
		if (k != 0)
			*zp++ = k, zl++;
	}
	z->l = zl;
	safety_assert(z->l < BIGSIZE);
	safety_assert(z->l >= 0);
	safety_assert_log(zp - &z->d[0] == 1 + z->l,
		"diff=%d, z->l=%d", zp - &z->d[0], z->l);
}

static int
big_comp(bignum_t *x, bignum_t *y)
{
	int i, xl, yl;
	uint64 *xp, *yp;

	safety_assert(x->l < BIGSIZE);
	safety_assert(x->l >= 0);
	safety_assert(y->l < BIGSIZE);
	safety_assert(y->l >= 0);

	xl = x->l;
	yl = y->l;
	if (xl > yl)
		return 1;
	if (xl < yl)
		return -1;
	xp = &x->d[xl];
	yp = &y->d[xl];
	for (i = xl; i >= 0; i--, xp--, yp--) {
		uint64 a = *xp;
		uint64 b = *yp;

		if (a > b) return 1;
		else if (a < b) return -1;
	}
	return 0;
}

static int
sub_big(bignum_t *x, bignum_t *y, bignum_t *z)
{
	int xl, yl, zl, b, i;
	uint64 *xp, *yp, *zp;

	safety_assert(x->l < BIGSIZE);
	safety_assert(x->l >= 0);
	safety_assert(y->l < BIGSIZE);
	safety_assert(y->l >= 0);

	xl = x->l;
	yl = y->l;
	if (yl > xl)
		return 1;
	xp = &x->d[0];
	yp = &y->d[0];
	zp = &z->d[0];

	for (i = yl, b = 0; i >= 0; i--)
		SUB(*xp++, *yp++, *zp++, b);
	for (i = xl-yl; b && i > 0; i--) {
		uint64 x_sub;
		x_sub = *xp++;
		*zp++ = x_sub - 1;
		b = (x_sub == 0);
	}
	safety_assert(zp - &z->d[0] < BIGSIZE);
	for (; i > 0; i--)
		*zp++ = *xp++;
	safety_assert(zp - &z->d[0] < BIGSIZE);
	if (b)
		return 1;
	zl = xl;
	while (zl > 0 && *--zp == 0)
		zl--;
	z->l = zl;
	safety_assert(z->l < BIGSIZE);
	safety_assert_log(z->l >= 0, "z->l = %d", z->l);
	return 0;
}

static void
add_big(bignum_t *x, bignum_t *y, bignum_t *z)
{
	int xl, yl, k, i;
	uint64 *xp, *yp, *zp;

	safety_assert(x->l < BIGSIZE);
	safety_assert(x->l >= 0);
	safety_assert(y->l < BIGSIZE);
	safety_assert(y->l >= 0);

	xl = x->l;
	yl = y->l;
	if (yl > xl) {
		int tl;
		bignum_t *tn;
		tl = xl; xl = yl; yl = tl;
		tn = x; x = y; y = tn;
	}

	xp = &x->d[0];
	yp = &y->d[0];
	zp = &z->d[0];

	for (i = yl, k = 0; i >= 0; i--)
		ADD(*xp++, *yp++, *zp++, k);
	for (i = xl-yl; k && i > 0; i--) {
		uint64 z_add;
		z_add = *xp++ + 1;
		k = (z_add == 0);
		*zp++ = z_add;
	}
	for (; i > 0; i--)
		*zp++ = *xp++;
	if (k)
		*zp = 1, z->l = xl+1;
	else
		z->l = xl;
	safety_assert(z->l < BIGSIZE);
	safety_assert(z->l >= 0);
}

static int
qr(void)
{
	if (big_comp(&R, &S5) < 0) {
		if (big_comp(&R, &S2) < 0) {
			if (big_comp(&R, &S) < 0) {
				return 0;
			} else {
				sub_big(&R, &S, &R);
				return 1;
			}
		} else if (big_comp(&R, &S3) < 0) {
			sub_big(&R, &S2, &R);
			return 2;
		} else if (big_comp(&R, &S4) < 0) {
			sub_big(&R, &S3, &R);
			return 3;
		} else {
			sub_big(&R, &S4, &R);
			return 4;
		}
	} else if (big_comp(&R, &S7) < 0) {
		if (big_comp(&R, &S6) < 0) {
			sub_big(&R, &S5, &R);
			return 5;
		} else {
			sub_big(&R, &S6, &R);
			return 6;
		}
	} else if (big_comp(&R, &S9) < 0) {
		if (big_comp(&R, &S8) < 0) {
			sub_big(&R, &S7, &R);
			return 7;
		} else {
			sub_big(&R, &S8, &R);
			return 8;
		}
	} else {
		sub_big(&R, &S9, &R);
		return 9;
	}
}

/**
 * Initialized floating point formatting constants.
 *
 * This routine will be called as needed the first time the API is
 * used but is made public to allow setting a baseline when doing
 * timing measurements.
 */
G_GNUC_COLD void
float_init(void)
{
	int n, i, l;
	bignum_t *b;
	uint64 *xp, *zp, k;

	/*
	 * No need to grab mutex: if called externally, we're in tests and so
	 * we know we are single-threaded.
	 */

	five[0].l = l = 0;
	five[0].d[0] = 5;
	for (n = MAX_FIVE-1, b = &five[0]; n > 0; n--) {
		xp = &b->d[0];
		b++;
		zp = &b->d[0];
		for (i = l, k = 0; i >= 0; i--)
			MUL(*xp++, 5, *zp++, k);
		if (k != 0)
			*zp = k, l++;
		b->l = l;
		g_assert(b->l < BIGSIZE);
	}

#ifdef FLOAT_DEBUG
	for (n = 1, b = &five[0]; n <= MAX_FIVE; n++) {
		big_shift_left(b++, n, &R);
		print_big(&R);
		putchar('\n');
	}
	fflush(0);
#endif	/* FLOAT_DEBUG */

	float_inited = TRUE;
}

static int
add_cmp(int use_mp)
{
	int rl, ml, sl, suml;
	static bignum_t sum;

	rl = R.l;
	ml = (use_mp ? MP.l : MM.l);
	sl = S.l;

	suml = rl >= ml ? rl : ml;
	if ((sl > suml+1) || ((sl == suml+1) && (S.d[sl] > 1))) return -1;
	if (sl < suml) return 1;

	add_big(&R, (use_mp ? &MP : &MM), &sum);
	return big_comp(&sum, &S);
}

static uint64
float_decompose(double v, int *sign, int *ep)
{
	uint64 f;
	int e;
	union double_decomposition dc;

	STATIC_ASSERT(sizeof v == sizeof(dc.d));

	/* decompose float into sign, mantissa & exponent */
	dc.value = v;
	*sign = dc.d.s;
	e = dc.d.e;
	f = ((uint64) dc.d.mh << 32) | (uint32) dc.d.ml;

	if (e != 0) {
		*ep = e - bias - bitstoright;
		f |= (uint64) hidden_bit << 32;
	} else if (f != 0) {
		/* denormalized */
		*ep = 1 - bias - bitstoright;
	}

	return f;
}

/*
 * Safety buffer manipulation macros added by RAM.
 */

#define PUTINC_CHAR(x)					\
G_STMT_START {							\
	if (remain != 0) {					\
		*bp++ = (x);					\
		remain--;						\
	}									\
} G_STMT_END

#define PUT_CHAR(x)						\
G_STMT_START {							\
	if (remain != 0) {					\
		*bp = (x);						\
	}									\
} G_STMT_END

#define OUTDIG(d) 						\
G_STMT_START {							\
	PUTINC_CHAR((d) + '0');				\
	PUT_CHAR('\0');						\
	goto done;							\
} G_STMT_END

/* Signature changed by RAM, was:
   int float_dragon(char *dest, double v); */

/**
 * Format 64-bit floating point value into mantissa and exponent,
 * using a free format consisting of the minimum amount of digits
 * capable of correctly representing the floating point value.
 *
 * @param dest		where mantissa is written
 * @param len		length of destination buffer
 * @param v			the floating point value to format
 * @param exponent	where exponent is returned
 *
 * @return amount of characters formatted into destination buffer.
 */
size_t
float_dragon(char *dest, size_t len, double v, int *exponent)
{
	int sign, e = 0, f_n, m_n, i, d, tc1, tc2;
	uint64 f;
	int ruf, k, sl = 0, slr = 0;
	int use_mp;
	char *bp = dest;
	size_t remain = len;

	/*
	 * This code is not thread-safe because it uses global variables.
	 * Hence we need to funnel execution to limit access to one thread
	 * only, not counting recursion which we handle.
	 */

	THREAD_FUNNEL;

	if G_UNLIKELY(!float_inited)
		float_init();

	recursion_level++;
	g_assert(recursion_level < FLOAT_RECURSION);

	/* decompose float into sign, mantissa & exponent */
	f = float_decompose(v, &sign, &e);

	if (sign)
		PUTINC_CHAR('-');

	if (f == 0) {
		k = 0;
		OUTDIG(0);
	}

	ruf = !(f & 1); /* ruf = (even? f) */

	/* Compute the scaling factor estimate, k */
	if (e > MIN_E) {
		k = estimate(e+52);
	} else {
		int n;
		uint64 y;

		for (n = e+52, y = (uint64)1 << 52; f < y; n--)
			y >>= 1;
		k = estimate(n);
	}

	if (e >= 0) {
		if (f != B_P1)
			use_mp = 0, f_n = e+1, s_n = 1, m_n = e;
		else
			use_mp = 1, f_n = e+2, s_n = 2, m_n = e;
	} else {
		if ((e == MIN_E) || (f != B_P1))
			use_mp = 0, f_n = 1, s_n = 1-e, m_n = 0;
		else
			use_mp = 1, f_n = 2, s_n = 2-e, m_n = 0;
	}
   
	/* Scale it! */
	if (k == 0) {
		short_shift_left(f, f_n, &R);
		one_shift_left(s_n, &S);
		one_shift_left(m_n, &MM);
		if (use_mp)
			one_shift_left(m_n+1, &MP);
		qr_shift = 1;
	} else if (k > 0) {
		s_n += k;
		if (m_n >= s_n)
			f_n -= s_n, m_n -= s_n, s_n = 0;
		else 
			f_n -= m_n, s_n -= m_n, m_n = 0;
		short_shift_left(f, f_n, &R);
		big_shift_left(&five[k-1], s_n, &S);
		one_shift_left(m_n, &MM);
		if (use_mp)
			one_shift_left(m_n+1, &MP);
		qr_shift = 0;
	} else {
		bignum_t *power = &five[-k-1];

		s_n += k;
		big_short_mul(power, f, &S);
		big_shift_left(&S, f_n, &R);
		one_shift_left(s_n, &S);
		big_shift_left(power, m_n, &MM);
		if (use_mp)
			big_shift_left(power, m_n+1, &MP);
		qr_shift = 1;
	}

	/* fixup */
	if (add_cmp(use_mp) <= -ruf) {
		k--;
		mul10(&R);
		mul10(&MM);
		if (use_mp)
			mul10(&MP);
	}

#ifdef FLOAT_DEBUG
	printf("\nk = %d\n", k);
	printf("R = "); print_big(&R);
	printf("\nS = "); print_big(&S);
	printf("\nM- = "); print_big(&MM);
	if (use_mp) printf("\nM+ = "), print_big(&MP);
	putchar('\n');
	fflush(0);
#endif	/* FLOAT_DEBUG */
   
	if (qr_shift) {
		sl = s_n / 64;
		slr = s_n % 64;
	} else {
		big_shift_left(&S, 1, &S2);
		add_big(&S2, &S, &S3);
		big_shift_left(&S2, 1, &S4);
		add_big(&S4, &S, &S5);
		add_big(&S4, &S2, &S6);
		add_big(&S4, &S3, &S7);
		big_shift_left(&S4, 1, &S8);
		add_big(&S8, &S, &S9);
	}

again:
	if (qr_shift) {
		/* Take advantage of the fact that S = (ash 1 s_n) */
		if (R.l < sl) {
			d = 0;
		} else if (R.l == sl) {
			uint64 *p;

			p = &R.d[sl];
			d = *p >> slr;
			*p &= ((uint64)1 << slr) - 1;
			for (i = sl; (i > 0) && (*p == 0); i--) p--;
			R.l = i;
		} else {
			uint64 *p;

			p = &R.d[sl+1];
			d = *p << (64 - slr) | *(p-1) >> slr;
			p--;
			*p &= ((uint64)1 << slr) - 1;
			for (i = sl; (i > 0) && (*p == 0); i--) p--;
			R.l = i;
		}
	} else {
		/* We need to do quotient-remainder */
		d = qr();
	}

	tc1 = big_comp(&R, &MM) < ruf;
	tc2 = add_cmp(use_mp) > -ruf;
	if (!tc1) {
		if (!tc2) {
			mul10(&R);
			mul10(&MM);
			if (use_mp)
				mul10(&MP);
			PUTINC_CHAR(d + '0');
			goto again;
		} else {
			OUTDIG(d+1);
		}
	} else {
		if (!tc2) {
			OUTDIG(d);
		} else {
			big_shift_left(&R, 1, &MM);
			if (big_comp(&MM, &S) == -1)
				OUTDIG(d);
			else
				OUTDIG(d+1);
		}
	}

	g_assert_not_reached();

done:
	*exponent = k;

	g_assert_log(ptr_diff(bp, dest) == len - remain,
		"ptr_diff=%zu, len=%zu, remain=%zu, len-remain=%zu",
		ptr_diff(bp, dest), len, remain, len - remain);

	recursion_level--;
	g_assert(recursion_level >= -1);

	THREAD_UNFUNNEL;

	return ptr_diff(bp, dest);
}


/* Fixed-format floating point printer
   A quick hack of the free-format printer */

/* Signature changed by RAM, was:
   int float_fixed(char *dest, double v, int prec); */

/**
 * Format 64-bit floating point value into mantissa and exponent,
 * using specified precision for the mantissa.
 *
 * @param dest		where mantissa is written
 * @param len		length of destination buffer
 * @param v			the floating point value to format
 * @param prec		precision for mantissa rounding
 * @param exponent	where exponent is returned
 *
 * @return amount of characters formatted into destination buffer.
 */
size_t
float_fixed(char *dest, size_t len, double v, int prec, int *exponent)
{
	int sign, e = 0, f_n, i, d, n;
	uint64 f;
	int k, sl = 0, slr = 0;
	char *bp = dest;
	size_t remain = len;
	size_t flen;

	g_assert(dest != NULL);
	g_assert(exponent != NULL);
	g_assert(size_is_positive(len));
	g_assert(prec >= 0);

	/*
	 * This code is not thread-safe because it uses global variables.
	 * Hence we need to funnel execution to limit access to one thread
	 * only, not counting recursion which we handle.
	 */

	THREAD_FUNNEL;

	if G_UNLIKELY(!float_inited)
		float_init();

	recursion_level++;
	g_assert(recursion_level < FLOAT_RECURSION);

	/* decompose float into sign, mantissa & exponent */
	f = float_decompose(v, &sign, &e);

	if (sign)
		PUTINC_CHAR('-');

	if (f == 0) {
		for (i = prec; i > 0; i--)
			PUTINC_CHAR('0');
		PUT_CHAR('\0');
		k = 0;
		flen = ptr_diff(bp, dest);
		goto done;
	}

	/* Compute the scaling factor estimate, k */
	if (e > MIN_E) {
		k = estimate(e+52);
	} else {
		uint64 y;

		for (n = e+52, y = (uint64)1 << 52; f < y; n--) y >>= 1;
		k = estimate(n);
	}

	if (e >= 0)
		f_n = e, s_n = 0;
	else
		f_n = 0, s_n = -e;

	/* Scale it! */
	if (k == 0) {
		short_shift_left(f, f_n, &R);
		one_shift_left(s_n, &S);
		qr_shift = 1;
	} else if (k > 0) {
		s_n += k;
		if (f_n >= s_n)
			f_n -= s_n, s_n = 0;
		else 
			s_n -= f_n, f_n = 0;
		short_shift_left(f, f_n, &R);
		big_shift_left(&five[k-1], s_n, &S);
		qr_shift = 0;
	} else {
		s_n += k;
		big_short_mul(&five[-k-1], f, &S);
		big_shift_left(&S, f_n, &R);
		one_shift_left(s_n, &S);
		qr_shift = 1;
	}

	/* fixup */
	if (big_comp(&R, &S) < 0) {
		k--;
		mul10(&R);
	}

	if (qr_shift) {
		sl = s_n / 64;
		slr = s_n % 64;
	} else {
		big_shift_left(&S, 1, &S2);
		add_big(&S2, &S, &S3);
		big_shift_left(&S2, 1, &S4);
		add_big(&S4, &S, &S5);
		add_big(&S4, &S2, &S6);
		add_big(&S4, &S3, &S7);
		big_shift_left(&S4, 1, &S8);
		add_big(&S8, &S, &S9);
	}

	for (n = prec;;) {
		if (qr_shift) {
			/* Take advantage of the fact that S = (ash 1 s_n) */
			if (R.l < sl) {
				d = 0;
			} else if (R.l == sl) {
				uint64 *p;

				p = &R.d[sl];
				d = *p >> slr;
				*p &= ((uint64)1 << slr) - 1;
				for (i = sl; (i > 0) && (*p == 0); i--)
					p--;
				R.l = i;
			} else {
				uint64 *p;

				p = &R.d[sl+1];
				d = *p << (64 - slr) | *(p-1) >> slr;
				p--;
				*p &= ((uint64)1 << slr) - 1;
				for (i = sl; (i > 0) && (*p == 0); i--)
					p--;
				R.l = i;
			}
		} else {
			/* We need to do quotient-remainder */
			d = qr();
		}

		PUTINC_CHAR(d + '0');
		if (--n == 0)
			break;
		mul10(&R);
	}

	big_shift_left(&R, 1, &MM);
	switch (big_comp(&MM, &S)) {
	case -1: /* No rounding needed */
		PUT_CHAR('\0');
		flen = ptr_diff(bp, dest);
		goto done;
	case 0: /* Exactly in the middle */
		PUTINC_CHAR('5');
		PUT_CHAR('\0');
		flen = ptr_diff(bp, dest);
		goto done;
	default:  /* Round up */
		flen = ptr_diff(bp, dest);
		*bp-- = '\0';
		break;
	}

	/* Patch string in-place to perform upwards rounding */

	for (n = prec; n > 0; n--) {
		char c;
		c = *bp;
		g_assert(ptr_cmp(bp, dest) >= 0);
		if (c != '9') {
			*bp = c + 1;
			goto done;
		}
		*bp-- = '0';
		flen--;
	}
	g_assert(ptr_diff(dest, bp) == 1);
	*++bp = '1';
	flen = 1;		/* Rounded up to one single non-zero digit */
	k++;
	/* FALL THROUGH */
done:
	*exponent = k;

	g_assert(size_is_positive(flen));
	g_assert(flen <= len);

	recursion_level--;
	g_assert(recursion_level >= -1);

	THREAD_UNFUNNEL;

	return flen;
}

/* vi: set ts=4 sw=4 cindent: */
