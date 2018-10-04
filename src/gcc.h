/*
 * Copyright (c) 2010-2016 Raphael Manfredi
 * Copyright (c) 2003-2009 Chrisian Biere
 * Copyright (c) 2001-2003 Richard Eckart
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
 * @ingroup core
 * @file
 *
 * Common gcc-specific macros.
 *
 * @author Richard Eckart
 * @date 2001-2003
 * @author Christian Biere
 * @date 2003-2009
 * @author Raphael Manfredi
 * @date 2010-2016
 */

#ifndef _gcc_h_
#define _gcc_h_

#if defined(__GNUC__) && defined(__GNUC_MINOR__)
/**
 * HAS_GCC allows conditionalization depending on the version of gcc
 * being used to compile the source.
 *
 * Check each version at "http://gcc.gnu.org/onlinedocs/" for
 * support.  Specific functionality may also be broken in some
 * compiler revisions, so it is useful to conditionalize on the
 * version.
 */
#define HAS_GCC(major, minor) \
	((__GNUC__ > (major)) || \
	 (__GNUC__ == (major) && __GNUC_MINOR__ >= (minor)))
#else
#define HAS_GCC(major, minor) 0
#endif

/*
 * If functions have this attribute GCC warns if it one of the specified
 * parameters is NULL. This macro takes a list of parameter indices. The
 * list must be embraced with parentheses for compatibility with C89
 * compilers. Example:
 *
 * void my_memcpy(void *dst, const void *src, size_t n) NON_NULL_PARAM((1, 2));
 */
#if defined(HASATTRIBUTE) && HAS_GCC(3, 3)
#define NON_NULL_PARAM(x) __attribute__((__nonnull__ x))
#else /* GCC < 3.3 */
#define NON_NULL_PARAM(x)
#endif

/**
 * This is the same as G_PRINTF() but for function pointers. Older versions
 * of GCC do not allow function attributes for function pointers.
 */
#if defined(HASATTRIBUTE) && HAS_GCC(3, 0)
#define G_PRINTF_PTR(x, y) __attribute__((format(_G_GNU_PRINTF_, (x), (y))))
#else /* GCC < 3.0 */
#define G_PRINTF_PTR(x, y)
#endif

/*
 * Functions using this attribute cause a warning if the returned
 * value is not used.
 */
#if defined(HASATTRIBUTE) && HAS_GCC(3, 4)
#define WARN_UNUSED_RESULT __attribute__((__warn_unused_result__))
#else /* GCC < 3.4 */
#define WARN_UNUSED_RESULT
#endif

/*
 * Instructs the compiler to emit code for this function even if it is
 * or seems to be unused.
 */
#if defined(HASATTRIBUTE) && HAS_GCC(3, 1)
#define G_USED __attribute__((__used__))
#else /* GCC < 3.1 || !GCC */
#define G_USED
#endif

/*
 * Let the compiler know that the function may be unused, hence it should
 * not emit any warning about it.
 *
 * Can also tag function parameters as remaining purposedly unused.
 */
#if defined(HASATTRIBUTE) && HAS_GCC(3, 1)
#define G_UNUSED __attribute__((__unused__))
#else	/* GCC < 3.1 */
#define G_UNUSED
#endif

/*
 * The antidote for WARN_UNUSED_RESULT. This attribute is sometimes
 * misused for functions that return a result which SHOULD NOT be
 * ignored in contrast to MUST NOT. Unfortunately, a simple "(void)"
 * does not suppress this warning.
 */
#define IGNORE_RESULT(x) \
	G_STMT_START { if (0 != (x)) {} }  G_STMT_END

/*
 * Functions using this attribute cause a warning if the variable
 * argument list does not contain a NULL pointer.
 */
#if defined(HASATTRIBUTE) && HAS_GCC(4, 0)
#define G_NULL_TERMINATED __attribute__((__sentinel__))
#else	/* GCC < 4 */
#define G_NULL_TERMINATED
#endif	/* GCC >= 4 */

/*
 * Define G_LIKELY() and G_UNLIKELY() so that they are available when
 * using GLib 1.2 as well. These allow optimization by static branch
 * prediction with GCC.
 */
#ifndef G_LIKELY
#if HAS_GCC(3, 4)	/* Just a guess, a Configure check would be better */
#define G_LIKELY(x)		(__builtin_expect((x), 1))
#define G_UNLIKELY(x)	(__builtin_expect((x), 0))
#else /* !GCC >= 3.4 */
#define G_LIKELY(x)		(x)
#define G_UNLIKELY(x)	(x)
#endif /* GCC >= 3.4 */
#endif /* !G_LIKELY */

/**
 * A pure function has no effects except its return value and the return value
 * depends only on the parameters and/or global variables.
 */
#if defined(HASATTRIBUTE) && HAS_GCC(2, 96)
#define G_PURE __attribute__((__pure__))
#else
#define G_PURE
#endif	/* GCC >= 2.96 */

#if defined(HASATTRIBUTE) && HAS_GCC(2, 4)
#define G_CONST __attribute__((__const__))
#else
#define G_CONST
#endif	/* GCC >= 2.4 */

/*
 * The __gnu__printf__ format appeared in gcc 4.4.
 */
#if HAS_GCC(4, 4)
#define _G_GNU_PRINTF_ __gnu_printf__
#else
#define _G_GNU_PRINTF_ __printf__
#endif

/**
 * Used to signal a function that does not return.
 *
 * The compiler can then optimize calls to that routine by not saving
 * registers before calling the routine.  However, this can mess up the
 * stack unwinding past these routines.
 */
#if defined(HASATTRIBUTE) && HAS_GCC(2, 4)
#define G_NORETURN __attribute__((__noreturn__))
#else
#define G_NORETURN
#endif	/* GCC >= 2.4 */

#if defined(HASATTRIBUTE) && HAS_GCC(3, 0)
#define G_MALLOC __attribute__((__malloc__)) WARN_UNUSED_RESULT
#else
#define G_MALLOC
#endif	/* GCC >= 3.0 */

/**
 * A hot function is optimized more aggressively.
 */
#if defined(HASATTRIBUTE) && HAS_GCC(4, 3)
#define G_HOT __attribute__((hot))
#else
#define G_HOT
#endif	/* GCC >= 4.3 */

/**
 * A cold function is unlikely executed, and is optimized for size rather
 * than speed.  All branch tests leading to it are marked "unlikely".
 */
#if defined(HASATTRIBUTE) && HAS_GCC(4, 3)
#define G_COLD __attribute__((cold))
#else
#define G_COLD
#endif	/* GCC >= 4.3 */

#if defined(HASATTRIBUTE) && HAS_GCC(3, 1)
#define ALWAYS_INLINE __attribute__((always_inline))
#else
#define ALWAYS_INLINE
#endif	/* GCC >= 3.1 */

#if defined(HASATTRIBUTE) && HAS_GCC(3, 1)
#define NO_INLINE __attribute__((noinline))
#else
#define NO_INLINE
#endif	/* GCC >= 3.1 */

#if defined(HASATTRIBUTE) && HAS_GCC(2, 7)
#define G_ALIGNED(n)	 __attribute__((aligned(n)))
#else
#define G_ALIGNED(n)
#endif	/* GCC >= 3.1 */

#if defined(HASATTRIBUTE) && defined(HAS_REGPARM)
#define REGPARM(n)	__attribute__((__regparm__((n))))
#else
#define REGPARM(n)
#endif	/* HAS_REGPARM */

/**
 * This avoid compilation warnings when handing "long long" types with gcc
 * invoked with options -pedantic and -ansi.
 */
#if HAS_GCC(2, 8)
#define G_EXTENSION __extension__
#else
#define G_EXTENSION
#endif

/*
 * Define G_PRINTF to use "GNU printf" argument form (gcc >= 4.4).
 * This ensures that "%m" is recognized as valid since the GNU libc supports it.
 */
#if defined(HASATTRIBUTE) && HAS_GCC(3, 0)
#define G_PRINTF(_fmt_, _arg_) \
	 __attribute__((__format__ (_G_GNU_PRINTF_, _fmt_, _arg_)))
#else
#define G_PRINTF(_fmt_, _arg_)
#endif

/**
 * G_FORMAT() identifies a printf()-like format argument for a function
 * returning a C string.
 */
#if defined(HASATTRIBUTE) && HAS_GCC(2, 5)
#define G_FORMAT(_arg_) __attribute__((__format_arg__ (_arg_)))
#else
#define G_FORMAT(_arg_)
#endif

/**
 * IS_CONSTANT() returns TRUE if the expression is a compile-time constant.
 */
#if HAS_GCC(3, 0)
#define IS_CONSTANT(x)	__builtin_constant_p(x)
#else
#define IS_CONSTANT(x)	FALSE
#endif

/*
 * Memory pre-fetching requests.
 *
 * One can request pre-fetch of a memory location for read or write, and
 * with a low (default), medium or high expected lifespan in the cache.
 */
#if HAS_GCC(3, 0)	/* Just a guess, a Configure check would be better */
#define G_PREFETCH_R(x)		__builtin_prefetch((x), 0, 0)
#define G_PREFETCH_W(x)		__builtin_prefetch((x), 1, 0)
#define G_PREFETCH_MED_R(x)	__builtin_prefetch((x), 0, 1)
#define G_PREFETCH_MED_W(x)	__builtin_prefetch((x), 1, 1)
#define G_PREFETCH_HI_R(x)	__builtin_prefetch((x), 0, 3)
#define G_PREFETCH_HI_W(x)	__builtin_prefetch((x), 1, 3)
#else /* !GCC >= 3.0 */
#define G_PREFETCH_R(x)
#define G_PREFETCH_W(x)
#define G_PREFETCH_MED_R(x)
#define G_PREFETCH_MED_W(x)
#define G_PREFETCH_HI_R(x)
#define G_PREFETCH_HI_W(x)
#endif /* GCC >= 3.0 */

/**
 * G_PRAGMA() lets one add a #pragma directive into another macro.
 */
#if HAS_GCC(3, 0)
#define G_PRAGMA(x)	_Pragma(#x)
#else
#define G_PRAGMA(x)
#endif

/**
 * G_IGNORE_PUSH() and G_IGNORE_POP can be used to disable a particular
 * warning purposedly for some section of the file and then later restore
 * the original warnings.
 */
#if HAS_GCC(4, 8)
#define G_IGNORE_PUSH(x) \
	G_PRAGMA(GCC diagnostic push) \
	G_PRAGMA(GCC diagnostic ignored #x)
#define G_IGNORE_POP G_PRAGMA(GCC diagnostic pop)
#else
#define G_IGNORE_PUSH(x)
#define G_IGNORE_POP
#endif

/**
 * G_IGNORE() can be used to disable a particular warning from here on.
 */
#if HAS_GCC(3, 0)
#define G_IGNORE(x) G_PRAGMA(GCC diagnostic ignored #x)
#else
#define G_IGNORE(x)
#endif

/**
 * G_FALL_THROUGH can be used to disable the fall-through warning in case
 * statements.
 */
#if HAS_GCC(7, 0)
#define G_FALL_THROUGH	__attribute__((fallthrough));
#else
#define G_FALL_THROUGH
#endif

/**
 * G_FAST can be used to tag a function for extreme optimizations.
 */
#if HAS_GCC(4, 4)
#define G_FAST	__attribute__((optimize(3)))
#else
#define G_FAST
#endif

/**
 * G_NO_OPTIMIZE can be used to turn-off optimizations for a function.
 */
#if HAS_GCC(4, 4)
#define G_NO_OPTIMIZE	__attribute__((optimize(0)))
#else
#define G_NO_OPTIMIZE
#endif

#endif	/* _gcc.h_ */

/* vi: set ts=4 sw=4 cindent: */
