/*
 * Copyright (c) 2014 Raphael Manfredi
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
 * Low-level array insertion and removal macros.
 *
 * These macros are used to insert, remove or make room for insertion at
 * a given array index.  The array is simply a plain memory region storing
 * each item contiguously in slots, all slots being equally-sized.
 *
 * There is no metadata attached to these arrays, which is why the macros
 * defined here all take a size parameter to specify how many items are held
 * in the memory region.
 *
 * Using these macros to handle insertion and removal from arrays factorizes
 * code and prevents typos, since some consistency is required between the
 * array name and the sizeof() call for instance.  They also add assertions to
 * dynamically ensure that the indices are correct with respect to the array
 * shape (capacity or current amount of items).
 *
 * @author Raphael Manfredi
 * @date 2014
 */

#ifndef _array_util_h_
#define _array_util_h_

/**
 * Remove item 'i' from an array of 'n' items (before removal).
 *
 * When the removed item is not the last one in the array, all subsequent
 * items are moved back to fill the hole created by that removed item.
 */
#define ARRAY_REMOVE(ary,i,n) G_STMT_START {	\
	g_assert_log((size_t) (i) < (size_t) (n),	\
		"%s(): index %zu out of array %s[%zu]",	\
		G_STRFUNC, (size_t) (i),				\
		# ary, (size_t)  (n));					\
	if G_LIKELY((i) != (n) - 1) {				\
		memmove(&ary[i], &ary[(i) + 1],			\
			((n) - 1 - (i)) * sizeof ary[0]);	\
	}											\
} G_STMT_END

/**
 * Remove item 'i' from an array of 'n' items (before removal), decrementing
 * the 'n' argument by one in the process.
 *
 * When the removed item is not the last one in the array, all subsequent
 * items are moved back to fill the hole created by that removed item.
 */
#define ARRAY_REMOVE_DEC(ary,i,n) G_STMT_START {	\
	(n)--;											\
	g_assert_log((size_t) (i) <= (size_t) (n),		\
		"%s(): index %zu out of array %s[%zu]",		\
		G_STRFUNC, (size_t) (i),					\
		# ary, (size_t)  (n) + 1);					\
	if G_LIKELY((i) != (n)) {						\
		memmove(&ary[i], &ary[(i) + 1],				\
			((n) - (i)) * sizeof ary[0]);			\
	}												\
} G_STMT_END

/**
 * Insert value at item 'i' within array of 'n' slots (extended before).
 *
 * When the item is not inserted as the last one in the array, all subsequent
 * items are shifted to make space for the insertion.
 *
 * The value may be a structure, in which case we rely on the compiler to
 * perform the struct copy into the array slot.
 */
#define ARRAY_INSERT(ary,i,n,val) G_STMT_START {	\
	g_assert_log((size_t) (i) < (size_t) (n),		\
		"%s(): index %zu out of array %s[%zu]",		\
		G_STRFUNC, (size_t) (i),					\
		# ary, (size_t)  (n));						\
	if G_LIKELY((i) != (n) - 1) {					\
		memmove(&ary[(i) + 1], &ary[i],				\
			((n) - 1 - (i)) * sizeof ary[0]);		\
	}												\
	ary[i] = (val);									\
} G_STMT_END

/**
 * Make room for value at slot 'i' within array of 'f' filled slots (0 .. f-1)
 * with a total capacity of 'n' slots.
 *
 * The 'i' slot MUST be in the range (0 .. f), i.e. either an insertion happens
 * within the consecutively filled slots, or we are inserting a new item
 * right after the last held item, and of course within the array range.
 *
 * The slot is NOT filled with any value, it is just made available by moving
 * all the items at or above the insertion point by one slot.
 */
#define ARRAY_MAKEROOM(ary,i,f,n) G_STMT_START {			\
	g_assert_log((size_t) (f) < (size_t) (n),				\
		"%s(): array %s[%zu] already holds %zu items",		\
		G_STRFUNC, # ary, (size_t) (n), (size_t) (f));		\
	g_assert_log((size_t) (i) <= (size_t) (f),				\
		"%s(): index %zu above fill %zu in array %s[%zu]",	\
		G_STRFUNC, (size_t) (i), (size_t) (f),				\
		# ary, (size_t)  (n));								\
	if G_LIKELY((i) < (f)) {								\
		memmove(&ary[(i) + 1], &ary[i],						\
			((f) - (i)) * sizeof ary[0]);					\
	}														\
} G_STMT_END

/**
 * Same as ARRAY_MAKEROOM, used when the size of the array is statically known.
 */
#define ARRAY_FIXED_MAKEROOM(ary,i,f) \
	ARRAY_MAKEROOM(ary,(i),(f),G_N_ELEMENTS(ary))

#endif /* _array_util_h_ */

/* vi: set ts=4 sw=4 cindent: */
