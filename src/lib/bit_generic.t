;#
;# $Id$
;#
;# Copyright (c) 2006, Christian Biere & Raphael Manfredi
;#
;#----------------------------------------------------------------------
;# This file is part of gtk-gnutella.
;#
;#  gtk-gnutella is free software; you can redistribute it and/or modify
;#  it under the terms of the GNU General Public License as published by
;#  the Free Software Foundation; either version 2 of the License, or
;#  (at your option) any later version.
;#
;#  gtk-gnutella is distributed in the hope that it will be useful,
;#  but WITHOUT ANY WARRANTY; without even the implied warranty of
;#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;#  GNU General Public License for more details.
;#
;#  You should have received a copy of the GNU General Public License
;#  along with gtk-gnutella; if not, write to the Free Software
;#  Foundation, Inc.:
;#      59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
;#----------------------------------------------------------------------
;#
;# This file is the template used to generate bit_array.h and bit_field.h.
;#

#include "halloc.h"

/**
 * Use the macro BIT_GENERIC_SIZE for allocating a properly sized bit <generic>
 * for "n" bits. Example:
 *
 * static bit_generic_t bits[BIT_GENERIC_SIZE(100)];
 */
#define BIT_GENERIC_SIZE(n) \
	((n) / BIT_GENERIC_BITSIZE + ((n) % BIT_GENERIC_BITSIZE ? 1 : 0))

/**
 * Use the macro BIT_GENERIC_BYTE_SIZE for dynamic allocation.
 * Example:
 *
 *  bit_generic_t *bits = malloc(BIT_GENERIC_BYTE_SIZE(num_bits));
 *
 **/
 #define BIT_GENERIC_BYTE_SIZE(n) (BIT_GENERIC_SIZE(n) * sizeof (bit_generic_t))

/**
 * Re-allocates "base" so that it can hold at least "n" bits
 * and initializes newly allocated bytes if necessary.
 *
 * @param base The base address of the bit <generic>, may be NULL.
 * @param n The number of bits the bit <generic> should hold.
 * @return the re-allocated bit <generic>.
 *
 * @attention DO NOT USE IN MEMORY ALLOCATING ROUTINES!
 */
static inline void
bit_generic_resize(bit_generic_t **base_ptr, size_t old_n, size_t new_n)
{
	size_t old_size, new_size;
	void *p;

	STATIC_ASSERT(0 == (BIT_GENERIC_BITSIZE & BIT_GENERIC_BITMASK));
	
	new_size = BIT_GENERIC_BYTE_SIZE(new_n);
	old_size = BIT_GENERIC_BYTE_SIZE(old_n);
	p = hrealloc(*base_ptr, new_size);
	if (old_size < new_size) {
		char *bytes = p;
		memset(&bytes[old_size], 0, new_size - old_size);
	}
	*base_ptr = p;
}

/**
 * Initializes the bit <generic> so that all bits are cleared. This
 * function MUST be used for all non-statically allocated bit arrays
 * before using it with any other bit <generic> function!
 *
 * @param base The base address of the bit <generic>, may be NULL.
 * @param n The number of bits the bit <generic> holds.
 */
static inline void 
bit_generic_init(bit_generic_t *base, size_t n)
{
	g_assert(!n || NULL != base);
	if (n) {
		memset(base, 0, BIT_GENERIC_BYTE_SIZE(n));
	}
}

/**
 * Sets bit number "i" of the bit <generic> "base".
 *
 * @param base The base address of the bit <generic> which must be initialized.
 * @param n The index of the bit to set counting from zero.
 * @note: For optimum performance, there are no checks at all.
 */
static inline ALWAYS_INLINE void
bit_generic_set(bit_generic_t *base, size_t i)
{
	BIT_GENERIC_WORD(base, i) |= BIT_GENERIC_BIT(base, i);
}

/**
 * Sets bit number "i" of the bit <generic> "base".
 * @param base The base address of the bit <generic> which must be initialized.
 * @param n The index of the bit to clear counting from zero.
 * @note: For optimum performance, there are no checks at all.
 */
static inline ALWAYS_INLINE void 
bit_generic_clear(bit_generic_t *base, size_t i)
{
	BIT_GENERIC_WORD(base, i) &= ~BIT_GENERIC_BIT(base, i);
}

/**
 * Flips bit number "i" of the bit <generic> "base".
 * @note: For optimum performance, there are no checks at all.
 *
 * @param base The base address of the bit <generic> which must be initialized.
 * @param n The index of the bit to flip counting from zero.
 * @return The new state of the bit.
 */
static inline ALWAYS_INLINE bool
bit_generic_flip(bit_generic_t *base, size_t i)
{
	return BIT_GENERIC_WORD(base, i) ^= BIT_GENERIC_BIT(base, i);
}

/**
 * Retrieves bit number "i" of the bit <generic> "base".
 * @note: For optimum performance, there are no checks at all.
 * @param base The base address of the bit <generic> which must be initialized.
 * @param n The index of the bit to read counting from zero.
 * @return TRUE if the bit is set, FALSE otherwise.
 */
static inline ALWAYS_INLINE bool
bit_generic_get(const bit_generic_t *base, size_t i)
{
	return 0 != (BIT_GENERIC_WORD(base, i) & BIT_GENERIC_BIT(base, i));
}

/**
 * Clears all bits starting at "from" up to "to" inclusive.
 * @note: For optimum performance, there are no checks at all.
 *
 * @param base The base address of the bit <generic> which must be initialized.
 * @param from The first bit.
 * @param to The last bit, must be equal to or above "from".
 * @return TRUE if the bit is set, FALSE otherwise.
 */
static inline void 
bit_generic_clear_range(bit_generic_t *base, size_t from, size_t to)
{
	size_t i;
	
	g_assert(from <= to);

	for (i = from; i <= to; /* NOTHING */) {
		if (0 == (i & BIT_GENERIC_BITMASK)) {
			size_t n = (to - i) >> BIT_GENERIC_BITSHIFT;

			if (n != 0) {
				size_t j = i >> BIT_GENERIC_BITSHIFT;

				i += n * BIT_GENERIC_BITSIZE;
				do {
					base[j++] = 0;
				} while (--n != 0);
				continue;
			}
		}
		bit_generic_clear(base, i++);
	}
}

/**
 * Sets all bits starting at "from" up to "to" inclusive.
 * @note: For optimum performance, there are no checks at all.
 *
 * @param base The base address of the bit <generic> which must be initialized.
 * @param from The first bit.
 * @param to The last bit, must be equal to or above "from".
 * @return TRUE if the bit is set, FALSE otherwise.
 */
static inline void 
bit_generic_set_range(bit_generic_t *base, size_t from, size_t to)
{
	size_t i;
	
	g_assert(from <= to);

	for (i = from; i <= to; /* NOTHING */) {
		if (0 == (i & BIT_GENERIC_BITMASK)) {
			size_t n = (to - i) >> BIT_GENERIC_BITSHIFT;

			if (n != 0) {
				size_t j = i >> BIT_GENERIC_BITSHIFT;

				i += n * BIT_GENERIC_BITSIZE;
				do {
					base[j++] = (bit_generic_t) -1;
				} while (--n != 0);
				continue;
			}
		}
		bit_generic_set(base, i++);
	}
}

/**
 * Peforms a linear scan for the first unset bit of the given bit <generic>.
 *
 * @param base The base address of the bit <generic> which must be initialized.
 * @param from The first bit.
 * @param to The last bit, must be equal to or above "from".
 * @return (size_t) -1, if no unset bit was found. On success the
 *        index of the first unset bit is returned.
 */
static inline size_t
bit_generic_first_clear(const bit_generic_t *base, size_t from, size_t to)
{
	size_t i;

	g_assert(from <= to);

	for (i = from; i <= to; /* NOTHING */) {
		if (0 == (i & BIT_GENERIC_BITMASK)) {
			size_t n = (to - i) >> BIT_GENERIC_BITSHIFT;

			if (n != 0) {
				size_t j = i >> BIT_GENERIC_BITSHIFT;

				while (n-- > 0) {
					if (base[j++] != (bit_generic_t) -1) {
						bit_generic_t value = base[j - 1];
						while (value & 0x1) {
							value >>= 1;
							i++;
						}
						return i;
					}
					i += BIT_GENERIC_BITSIZE;
				}
				continue;
			}
		}
		if (!bit_generic_get(base, i))
			return i;
		i++;
	}

	return (size_t) -1;
}

/**
 * Peforms a linear scan for the first set bit of the given bit <generic>.
 *
 * @param base The base address of the bit <generic> which must be initialized.
 * @param from The first bit.
 * @param to The last bit, must be equal to or above "from".
 * @return (size_t) -1, if no unset bit was found. On success the
 *        index of the first set bit is returned.
 */
static inline size_t
bit_generic_first_set(const bit_generic_t *base, size_t from, size_t to)
{
	size_t i;

	g_assert(from <= to);

	for (i = from; i <= to; /* NOTHING */) {
		if (0 == (i & BIT_GENERIC_BITMASK)) {
			size_t n = (to - i) >> BIT_GENERIC_BITSHIFT;

			if (n != 0) {
				size_t j = i >> BIT_GENERIC_BITSHIFT;

				while (n-- > 0) {
					if (base[j++] != 0) {
						bit_generic_t value = base[j - 1];
						while (0 == (value & 0x1)) {
							value >>= 1;
							i++;
						}
						return i;
					}
					i += BIT_GENERIC_BITSIZE;
				}
				continue;
			}
		}
		if (bit_generic_get(base, i))
			return i;
		i++;
	}

	return (size_t) -1;
}

/**
 * Peforms a linear scan for the last set bit of the given bit <generic>.
 *
 * @param base The base address of the bit <generic> which must be initialized.
 * @param from The first bit.
 * @param to The last bit, must be equal to or above "from".
 * @return (size_t) -1, if no set bit was found. On success the
 *        index of the last set bit is returned.
 */
static inline size_t
bit_generic_last_set(const bit_generic_t *base, size_t from, size_t to)
{
	size_t i = to;

	g_assert(from <= to);

	for (;;) {
		if (BIT_GENERIC_BITMASK == (i & BIT_GENERIC_BITMASK)) {
			size_t n = (i - from) >> BIT_GENERIC_BITSHIFT;

			if (n != 0) {
				size_t j = i >> BIT_GENERIC_BITSHIFT;

				while (n-- > 0) {
					if (base[j--] != 0) {
						bit_generic_t value = base[j + 1];
						bit_generic_t mask = 1UL << (BIT_GENERIC_BITSIZE - 1);
						while (mask != 0) {
							if (value & mask)
								return i;
							mask >>= 1;
							i--;
						}
						g_assert_not_reached();
					}
					if (i == from)
						break;
					i -= BIT_GENERIC_BITSIZE;
				}
				continue;
			}
		}
		if (bit_generic_get(base, i))
			return i;
		if (i == from)
			break;
		i--;
	}

	return (size_t) -1;
}

#undef BIT_GENERIC_BIT
#undef BIT_GENERIC_BITMASK
#undef BIT_GENERIC_BITSHIFT
#undef BIT_GENERIC_WORD

#endif /* _bit_generic_h_ */
/* vi: set ts=4 sw=4 cindent: */
