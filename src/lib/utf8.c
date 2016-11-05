/*
 * Copyright (c) 2002-2003, 2010, Raphael Manfredi
 * Copyright (c) 2004-2006, Christian Biere
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
 * Unicode Transformation Format 8 bits.
 *
 * This code has been heavily inspired by utf8.c/utf8.h from Perl 5.6.1,
 * written by Larry Wall et al.
 *
 * @author Raphael Manfredi
 * @date 2002-2003, 2010
 * @author Christian Biere
 * @date 2004-2006
 */

#include "common.h"

#ifdef ENABLE_NLS
#include <libintl.h>
#endif /* ENABLE_NLS */

#include <locale.h>

#if defined(I_LIBCHARSET) && defined(HAS_LOCALE_CHARSET)
#include <libcharset.h>
#else /* !I_LIBCHARSET */

#ifdef I_LANGINFO
#include <langinfo.h>
#endif

#endif /* I_LIBCHARSET */

#ifdef I_ICONV
#include <iconv.h>
#endif	/* I_ICONV */

#include "utf8_tables.h"

#include "utf8.h"

#include "ascii.h"
#include "atoms.h"
#include "concat.h"
#include "debug.h"
#include "endian.h"
#include "halloc.h"
#include "hikset.h"
#include "hstrfn.h"
#include "htable.h"
#include "mempcpy.h"
#include "misc.h"
#include "path.h"
#include "pslist.h"
#include "random.h"
#include "str.h"
#include "stringify.h"
#include "unsigned.h"
#include "walloc.h"

#include "override.h"		/* Must be the last header included */

/**
 * If ui_uses_utf8_encoding() returns TRUE, it is assumed that the
 * user-interface passes only valid UTF-8 strings. It affects only those
 * functions that are explicitely defined to handle UI strings as input or
 * output. This allows us to reduce the number of conversions. For example, if
 * a function specification permits that the original string may be returned, we
 * will do that instead of creating a copy. If ui_uses_utf8_encoding() returns
 * FALSE, it is assumed that the user-interface uses the locale's encoding for
 * its strings.
 */
static inline bool
ui_uses_utf8_encoding(void)
{
#ifdef USE_GTK2
	return TRUE;
#else  /* !USE_GTK2 */
	return FALSE;
#endif /* USE_GTK2 */
}

static void unicode_compose_init(void);

static bool unicode_compose_init_passed;
static bool locale_init_passed;

void utf8_regression_checks(void);
size_t utf8_decompose_nfd(const char *in, char *out, size_t size);
size_t utf8_decompose_nfkd(const char *in, char *out, size_t size);
size_t utf32_strmaxlen(const uint32 *s, size_t maxlen);
size_t utf32_strlen(const uint32 *s);

/**
 * use_icu is set to TRUE if the initialization of ICU succeeded.
 * If it fails, we'll fall back to the non-ICU behaviour.
 */
static bool use_icu = FALSE;

/** Used by is_latin_locale(). It is initialized by locale_init(). */
static bool latin_locale = FALSE;

#if 0  /*  xxxUSE_ICU */
static UConverter *conv_icu_locale = NULL;
static UConverter *conv_icu_utf8 = NULL;
#endif /* xxxUSE_ICU */

/**
 * This table records mappings "charset name" -> struct conv_to_utf8.
 */
static hikset_t *charset2conv_to_utf8;

enum conv_to_utf8_magic { CONV_TO_UTF8_MAGIC = 0x0a829276 };

struct conv_to_utf8 {
	enum conv_to_utf8_magic magic;
	const char *name;		/**< Name of the source charset (atom) */
	iconv_t cd;		/**< iconv() conversion descriptor; -1 or iconv_open()ed */
	bool is_ascii;		/**< Set to TRUE if name is "ASCII" */
	bool is_utf8;		/**< Set to TRUE if name is "UTF-8" */
	bool is_iso8859;	/**< Set to TRUE if name matches "ISO-8859-*" */
};

static inline void
conv_to_utf8_check(const struct conv_to_utf8 * const cu)
{
	g_assert(cu != NULL);
	g_assert(CONV_TO_UTF8_MAGIC == cu->magic);
}

static char *charset = NULL;	/** Name of the locale charset */
static htable_t *utf32_compose_roots;

/** A single-linked list of conv_to_utf8 structs. The first one is used
 ** for converting from the primary charset. Additional charsets are optional.
 **/
static pslist_t *sl_filename_charsets = NULL;

static iconv_t cd_locale_to_utf8 = (iconv_t) -1; /** Mainly used for Gtk+ 1.2 */
static iconv_t cd_utf8_to_locale = (iconv_t) -1; /** Mainly used for Gtk+ 1.2 */
static iconv_t cd_utf8_to_filename = (iconv_t) -1;
static iconv_t cd_utf8_to_iso8859_1 = (iconv_t) -1;

#define UTF8_CPU_CACHELINE	32		/* Length of cache in bytes, for prefetch */

enum utf8_cd {
	UTF8_CD_ISO8859_1,
	UTF8_CD_ISO8859_6,
	UTF8_CD_ISO8859_7,
	UTF8_CD_ISO8859_8,
	UTF8_CD_SJIS,
	UTF8_CD_EUC_JP,
	UTF8_CD_KOI8_R,

	NUM_UTF8_CDS,
	UTF8_CD_INVALID		= -1
};

static struct {
	iconv_t cd;				/**< iconv() conversion descriptor; may be -1 */
	const char *name;		/**< Name of the source charset */
	const enum utf8_cd id;	/**< Enumerated ID of the converter */
	bool initialized;		/**< Whether initialization of "cd" was attempted */
} utf8_cd_tab[] = {
#define D(name, id) (iconv_t) -1, (name), (id), FALSE
	{ D("ISO-8859-1",	UTF8_CD_ISO8859_1) },
	{ D("ISO-8859-6",	UTF8_CD_ISO8859_6) },
	{ D("ISO-8859-7",	UTF8_CD_ISO8859_7) },
	{ D("ISO-8859-8",	UTF8_CD_ISO8859_8) },
	{ D("SJIS",			UTF8_CD_SJIS) },
	{ D("EUC-JP",		UTF8_CD_EUC_JP) },
	{ D("KOI8-R",		UTF8_CD_KOI8_R) },
#undef D
};

/**
 * Looks up a "to UTF-8" converter by source charset name.
 */
static enum utf8_cd
utf8_name_to_cd(const char *name)
{
	uint i;

	STATIC_ASSERT(N_ITEMS(utf8_cd_tab) == NUM_UTF8_CDS);
	for (i = 0; i < N_ITEMS(utf8_cd_tab); i++)
		if (0 == strcmp(name, utf8_cd_tab[i].name))
			return utf8_cd_tab[i].id;

	return UTF8_CD_INVALID;
}

/**
 * Determine the name of the source charset of a converter.
 */
static const char *
utf8_cd_to_name(enum utf8_cd id)
{
	uint i = (uint) id;

	g_assert(i < N_ITEMS(utf8_cd_tab));
	STATIC_ASSERT(N_ITEMS(utf8_cd_tab) == NUM_UTF8_CDS);

	g_assert(utf8_cd_tab[i].id == id);
	return utf8_cd_tab[i].name;
}

/**
 * Get the iconv() conversion descriptor of a converter.
 */
static iconv_t
utf8_cd_get(enum utf8_cd id)
{
	uint i = (uint) id;

	g_assert(i < N_ITEMS(utf8_cd_tab));

	if (!utf8_cd_tab[i].initialized) {
		const char *cs;

		utf8_cd_tab[i].initialized = TRUE;
		cs = utf8_cd_tab[i].name;
		g_assert(cs);

		if ((iconv_t) -1 == (utf8_cd_tab[i].cd = iconv_open("UTF-8", cs)))
			g_warning("iconv_open(\"UTF-8\", \"%s\") failed.", cs);
	}

	return utf8_cd_tab[i].cd;
}

bool
locale_is_utf8(void)
{
	static bool initialized, is_utf8;

	if (!initialized) {
		initialized = TRUE;
		g_assert(NULL != charset);
		is_utf8 = 0 == strcmp(charset, "UTF-8");
	}
	return is_utf8;
}

static const char *
primary_filename_charset(void)
{
	const struct conv_to_utf8 *t;

	g_assert(sl_filename_charsets);

	t = sl_filename_charsets->data;
	conv_to_utf8_check(t);
	g_assert(t->name);

	return t->name;
}

static inline bool
primary_filename_charset_is_utf8(void)
{
	const struct conv_to_utf8 *t;

	g_assert(sl_filename_charsets);
	t = sl_filename_charsets->data;
	conv_to_utf8_check(t);

	return t->is_utf8;
}

static inline G_PURE uint
utf8_skip(uchar c)
{
	/*
	 * How wide is an UTF-8 encoded char, depending on its first byte?
	 *
	 * See Unicode 4.1.0, Chapter 3.10, Table 3-6
	 */
	static const uint8 utf8len[(size_t) (uchar) -1 + 1] = {
		1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,	/* 0x00-0x0F */
		1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,	/* 0x10-0x1F */
		1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,	/* 0x20-0x2F */
		1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,	/* 0x30-0x3F */
		1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,	/* 0x40-0x4F */
		1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,	/* 0x50-0x5F */
		1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,	/* 0x60-0x6F */
		1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,	/* 0x70-0x7F */

		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,	/* 0x80-0x8F */
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,	/* 0x90-0x9F */
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,	/* 0xA0-0xAF */
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,	/* 0xB0-0xBF */

		0,0,								/* 0xC0-0xC1 */
		    2,2,2,2,2,2,2,2,2,2,2,2,2,2,	/* 0xC2-0xCF */
		2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,	/* 0xD0-0xDF */

		3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,	/* 0xE0-0xEF */

		4,4,4,4,4,							/* 0xF0-0xF4 */
				  0,0,0,0,0,0,0,0,0,0,0,	/* 0xF5-0xFF */
	};

	return utf8len[c];
}

static const uint8 utf8len_mark[] = {
	0x00, 0x00, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC
};

#define UTF8_LENGTH_MARK(len)	utf8len_mark[len]

/*
 * The following table is from Unicode 3.1.
 *
 * Code Points           1st Byte    2nd Byte    3rd Byte    4th Byte
 *
 *    U+0000..U+007F      00..7F
 *    U+0080..U+07FF      C2..DF      80..BF
 *    U+0800..U+0FFF      E0          A0..BF      80..BF
 *    U+1000..U+FFFF      E1..EF      80..BF      80..BF
 *   U+10000..U+3FFFF     F0          90..BF      80..BF      80..BF
 *   U+40000..U+FFFFF     F1..F3      80..BF      80..BF      80..BF
 *  U+100000..U+10FFFF    F4          80..8F      80..BF      80..BF
 */

#define CHAR(x)					((uchar) (x))
#define UTF8_BYTE_MARK			0x80
#define UTF8_BYTE_MASK			0xbf
#define UTF8_IS_ASCII(x)		(CHAR(x) < UTF8_BYTE_MARK)
#define UTF8_IS_START(x)		(CHAR(x) >= 0xc0 && CHAR(x) <= 0xfd)
#define UTF8_IS_CONTINUATION(x)	\
	(CHAR(x) >= UTF8_BYTE_MARK && CHAR(x) <= UTF8_BYTE_MASK)
#define UTF8_IS_CONTINUED(x)	(CHAR(x) & UTF8_BYTE_MARK)

#define UTF8_CONT_MASK			(CHAR(0x3f))
#define UTF8_ACCU_SHIFT			6
#define UTF8_ACCUMULATE(o,n)	\
	(((o) << UTF8_ACCU_SHIFT) | (CHAR(n) & UTF8_CONT_MASK))

#define UNI_SURROGATE_FIRST		0xd800
#define UNI_SURROGATE_SECOND	0xdc00
#define UNI_SURROGATE_LAST		0xdfff
#define UNI_HANGUL_FIRST		0xac00
#define UNI_HANGUL_LAST			0xd7a3
#define UNI_REPLACEMENT			0xfffd
#define UNI_BYTE_ORDER_MARK		0xfffe
#define UNI_ILLEGAL				0xffff

#define UNICODE_IS_SURROGATE(x)	utf32_is_surrogate(x)

#define UNICODE_IS_HANGUL(x)	\
	((x) >= UNI_HANGUL_FIRST && (x) <= UNI_HANGUL_LAST)

#define UNICODE_IS_ASCII(x)				((x) < 0x0080U)
#define UNICODE_IS_REPLACEMENT(x)		((x) == UNI_REPLACEMENT)
#define UNICODE_IS_BYTE_ORDER_MARK(x)	((0xFFFFU & (x)) == UNI_BYTE_ORDER_MARK)
#define UNICODE_IS_BOM(x) 				UNICODE_IS_BYTE_ORDER_MARK(x)
#define UNICODE_IS_ILLEGAL(x) \
	((x) > 0x10FFFFU || (UNI_ILLEGAL & (x)) == UNI_ILLEGAL)

/**
 * Determines the UTF-8 byte length for the given Unicode codepoint.
 *
 * @param uc an UTF-32 codepoint.
 * @return	The exact amount of bytes necessary to store this codepoint in
 *			UTF-8 encoding.
 */
static inline G_CONST uint
uniskip(uint32 uc)
{
	return uc < 0x80U ? 1 : uc < 0x800 ? 2 : uc < 0x10000 ? 3 : 4;
}

/**
 * @param uc the unicode character to encode.
 * @returns 0 if the unicode codepoint is invalid. Otherwise the
 *          length of the UTF-8 character is returned.
 */
static inline uint
utf8_encoded_char_len(uint32 uc)
{
	return utf32_bad_codepoint(uc) ? 0 : uniskip(uc);
}

/**
 * Encodes Unicode character as UTF-8 into buffer.
 *
 * @param uc	the Unicode character to encode.
 * @param buf	the destination buffer.
 * @param size	the length of the destination buffer.
 *
 * @returns 0 if the Unicode character could not be encoded.
 * Otherwise the length of the generated UTF-8 character.
 */
uint NON_NULL_PARAM((2))
utf8_encode_char(uint32 uc, char *buf, size_t size)
{
	uint len, i;

	if (UNICODE_IS_ASCII(uc)) {
		*buf = uc;
		return 1;
	}

	len = utf8_encoded_char_len(uc);
	if (G_LIKELY(len <= size)) {
		i = len;
		while (i > 1) {
			i--;
			buf[i] = (uc | UTF8_BYTE_MARK) & UTF8_BYTE_MASK;
			uc >>= UTF8_ACCU_SHIFT;
		}
		buf[0] = uc | UTF8_LENGTH_MARK(len);
	} else {
		len = 0;
	}

	return len;
}

static inline uint
utf32_combining_class(uint32 uc)
{
	if (UNICODE_IS_ASCII(uc))
		return 0;

#define GET_ITEM(i)	(utf32_comb_class_lut[(i)].uc)
#define FOUND(i)	return utf32_comb_class_lut[(i)].cc

	/* Perform a binary search to find ``uc'' */
	BINARY_SEARCH(uint32, uc, N_ITEMS(utf32_comb_class_lut), CMP,
		GET_ITEM, FOUND);

#undef FOUND
#undef GET_ITEM

	return 0;
}

static inline int
block_id_cmp(size_t i, uint32 uc)
{
	if (uc < utf32_block_id_lut[i].start)
		return 1;
	if (uc > utf32_block_id_lut[i].end)
		return -1;

	return 0;
}

static inline uint
utf32_block_id(uint32 uc)
{
#define GET_ITEM(i)	(i)
#define FOUND(i)	return 1 + (i)

	/* Perform a binary search to find ``uc'' */
	BINARY_SEARCH(uint32, uc, N_ITEMS(utf32_block_id_lut), block_id_cmp,
		GET_ITEM, FOUND);

#undef FOUND
#undef GET_ITEM

	return 0;
}

static inline bool
utf32_composition_exclude(uint32 uc)
{
#define GET_ITEM(i)	(utf32_composition_exclusions[(i)])
#define FOUND(i)	return TRUE

	/* Perform a binary search to find ``uc'' */
	BINARY_SEARCH(uint32, uc, N_ITEMS(utf32_composition_exclusions), CMP,
		GET_ITEM, FOUND);

#undef FOUND
#undef GET_ITEM

	return FALSE;
}

static inline int
general_category_cmp(size_t i, uint32 uc)
{
	uint32 uc2, uc3;

	uc2 = utf32_general_category_lut[i].uc;
	if (uc == uc2)
		return 0;
	if (uc < uc2)
		return 1;

	uc3 = uc2 + utf32_general_category_lut[i].len;
	return uc < uc3 ? 0 : -1;
}

static inline uni_gc_t
utf32_general_category(uint32 uc)
{
#define GET_ITEM(i)	(i)
#define FOUND(i)	return utf32_general_category_lut[(i)].gc

	/* Perform a binary search to find ``uc'' */
	BINARY_SEARCH(size_t, uc, N_ITEMS(utf32_general_category_lut),
		general_category_cmp, GET_ITEM, FOUND);

#undef FOUND
#undef GET_ITEM

	return UNI_GC_OTHER_NOT_ASSIGNED;
}

static inline int
normalization_special_cmp(size_t i, uint32 uc)
{
	uint32 uc2, uc3;

	uc2 = utf32_normalization_specials[i].uc;
	if (uc == uc2)
		return 0;
	if (uc < uc2)
		return 1;

	uc3 = uc2 + utf32_normalization_specials[i].len;
	return uc < uc3 ? 0 : -1;
}

static inline bool
utf32_is_normalization_special(uint32 uc)
{
#define GET_ITEM(i)	(i)
#define FOUND(i)	return TRUE

	/* Perform a binary search to find ``uc'' */
	BINARY_SEARCH(size_t, uc, N_ITEMS(utf32_normalization_specials),
		normalization_special_cmp, GET_ITEM, FOUND);

#undef FOUND
#undef GET_ITEM

	return FALSE;
}

#if defined(TEST_UTF8_DECODER)
/**
 * @returns the character value of the first character in the string `s',
 * which is assumed to be in UTF-8 encoding and no longer than `len'.
 * `retlen' will be set to the length, in bytes, of that character.
 *
 * If `s' does not point to a well-formed UTF-8 character, the behaviour
 * is dependent on the value of `warn'.  When FALSE, it is assumed that
 * the caller will raise a warning, and this function will silently just
 * set `retlen' to 0 and return zero.
 */
static uint32
utf8_decode_char(const char *s, int len, uint *retlen, bool warn)
{
	uint32 v = *s;
	uint32 ov = 0;
	int clen = 1;
	int expectlen = 0;
	int warning = -1;
	char msg[128];

	g_assert(s);

#define UTF8_WARN_EMPTY				0
#define UTF8_WARN_CONTINUATION		1
#define UTF8_WARN_NON_CONTINUATION	2
#define UTF8_WARN_FE_FF				3
#define UTF8_WARN_SHORT				4
#define UTF8_WARN_OVERFLOW			5
#define UTF8_WARN_SURROGATE			6
#define UTF8_WARN_BOM				7
#define UTF8_WARN_LONG				8
#define UTF8_WARN_ILLEGAL			9

	if (len == 0) {
		warning = UTF8_WARN_EMPTY;
		goto malformed;
	}

	if (UTF8_IS_ASCII(v)) {
		if (retlen)
			*retlen = 1;
		return *s;
	}

	if (UTF8_IS_CONTINUATION(v)) {
		warning = UTF8_WARN_CONTINUATION;
		goto malformed;
	}

	if (UTF8_IS_START(v) && len > 1 && !UTF8_IS_CONTINUATION(s[1])) {
		warning = UTF8_WARN_NON_CONTINUATION;
		goto malformed;
	}

	if (v == 0xfe || v == 0xff) {
		warning = UTF8_WARN_FE_FF;
		goto malformed;
	}

	if      (!(v & 0x20)) { clen = 2; v &= 0x1f; }
	else if (!(v & 0x10)) { clen = 3; v &= 0x0f; }
	else if (!(v & 0x08)) { clen = 4; v &= 0x07; }
	else if (!(v & 0x04)) { clen = 5; v &= 0x03; }
	else if (!(v & 0x02)) { clen = 6; v &= 0x01; }
	else if (!(v & 0x01)) { clen = 7; v = 0; }

	if (retlen)
		*retlen = clen;

	expectlen = clen;

	if (len < expectlen) {
		warning = UTF8_WARN_SHORT;
		goto malformed;
	}

	for (clen--, s++, ov = v; clen; clen--, s++, ov = v) {
		if (!UTF8_IS_CONTINUATION(*s)) {
			s--;
			warning = UTF8_WARN_NON_CONTINUATION;
			goto malformed;
		} else
			v = UTF8_ACCUMULATE(v, *s);

		if (v < ov) {
			warning = UTF8_WARN_OVERFLOW;
			goto malformed;
		} else if (v == ov) {
			warning = UTF8_WARN_LONG;
			goto malformed;
		}
	}

	if (UNICODE_IS_SURROGATE(v)) {
		warning = UTF8_WARN_SURROGATE;
		goto malformed;
	} else if (UNICODE_IS_BYTE_ORDER_MARK(v)) {
		warning = UTF8_WARN_BOM;
		goto malformed;
	} else if ((uint) expectlen > uniskip(v)) {
		warning = UTF8_WARN_LONG;
		goto malformed;
	} else if (UNICODE_IS_ILLEGAL(v)) {
		warning = UTF8_WARN_ILLEGAL;
		goto malformed;
	}

	return v;

malformed:

	if (!warn) {
		if (retlen)
			*retlen = 0;
		return 0;
	}

	switch (warning) {
	case UTF8_WARN_EMPTY:
		str_bprintf(msg, sizeof(msg), "empty string");
		break;
	case UTF8_WARN_CONTINUATION:
		str_bprintf(msg, sizeof(msg),
			"unexpected continuation byte 0x%02lx", (ulong) v);
		break;
	case UTF8_WARN_NON_CONTINUATION:
		str_bprintf(msg, sizeof(msg),
			"unexpected non-continuation byte 0x%02lx "
			"after start byte 0x%02lx", (ulong) s[1], (ulong) v);
		break;
	case UTF8_WARN_FE_FF:
		str_bprintf(msg, sizeof(msg), "byte 0x%02lx", (ulong) v);
		break;
	case UTF8_WARN_SHORT:
		str_bprintf(msg, sizeof(msg), "%d byte%s, need %d",
			len, plural(len), expectlen);
		break;
	case UTF8_WARN_OVERFLOW:
		str_bprintf(msg, sizeof(msg), "overflow at 0x%02lx, byte 0x%02lx",
			(ulong) ov, (ulong) *s);
		break;
	case UTF8_WARN_SURROGATE:
		str_bprintf(msg, sizeof(msg), "UTF-16 surrogate 0x04%lx", (ulong) v);
		break;
	case UTF8_WARN_BOM:
		str_bprintf(msg, sizeof(msg), "byte order mark 0x%04lx", (ulong) v);
		break;
	case UTF8_WARN_LONG:
		str_bprintf(msg, sizeof(msg), "%d byte%s, need %d",
			expectlen, plural(expectlen), uniskip(v));
		break;
	case UTF8_WARN_ILLEGAL:
		str_bprintf(msg, sizeof(msg), "character 0x%04lx", (ulong) v);
		break;
	default:
		str_bprintf(msg, sizeof(msg), "unknown reason");
		break;
	}

	g_warning("malformed UTF-8 character: %s", msg);

	if (retlen)
		*retlen = expectlen ? expectlen : len;

	return 0;
}

/* Slower but correct, keep it around for consistency checks. */
static uint32
utf8_decode_char_less_fast(const char *s, uint *retlen)
{
	uint32 v = *s;
	uint32 nv;
	uint32 ov = 0;
	int clen = 1;
	int expectlen = 0;

	g_assert(s);

	if (UTF8_IS_ASCII(v)) {
		if (retlen)
			*retlen = 1;
		return *s;
	}

	if (UTF8_IS_CONTINUATION(v))
		goto malformed;

	nv = s[1];

	if (UTF8_IS_START(v) && !UTF8_IS_CONTINUATION(nv))
		goto malformed;

	if (v == 0xfe || v == 0xff)
		goto malformed;

	if      (!(v & 0x20)) { clen = 2; v &= 0x1f; }
	else if (!(v & 0x10)) { clen = 3; v &= 0x0f; }
	else if (!(v & 0x08)) { clen = 4; v &= 0x07; }
	else if (!(v & 0x04)) { clen = 5; v &= 0x03; }
	else if (!(v & 0x02)) { clen = 6; v &= 0x01; }
	else if (!(v & 0x01)) { clen = 7; v = 0; }

	if (retlen)
		*retlen = clen;

	expectlen = clen;

	/* nv was already set above as s[1], no need to read it again */

	for (clen--, s++, ov = v; clen; clen--, nv = *(++s), ov = v) {
		if (!UTF8_IS_CONTINUATION(nv))
			goto malformed;

		v = UTF8_ACCUMULATE(v, nv);

		if (v <= ov)
			goto malformed;
	}

	if (UNICODE_IS_SURROGATE(v))		goto malformed;
	if (UNICODE_IS_BYTE_ORDER_MARK(v))	goto malformed;
	if ((uint) expectlen > uniskip(v))	goto malformed;
	if (UNICODE_IS_ILLEGAL(v))			goto malformed;

	return v;

malformed:
	if (retlen)
		*retlen = 0;

	return 0;
}
#endif /* TEST_UTF8_DECODER */

/**
 * Decode a long-character (more than one byte).
 *
 * @param s			the second byte of the character
 * @param uc		the first byte we read
 * @param retlen	initial amount of chars to expect, updated if char invalid
 *
 * @returns the decoded character value.
 *
 * If `s' does not point to the second byte of a well-formed UTF-8 character,
 * `retlen' is set to 0 and the function returns 0.
 */
static uint32 G_HOT
utf8_decode_large_char_fast(const char *s, uint32 uc, uint *retlen)
{
	uchar c = *s;
	uint i = uc & 0x3F;
	uint n = *retlen;

	/* The second byte needs special handling */

	if (c > utf8_2nd_byte_tab[i].end || c < utf8_2nd_byte_tab[i].start)
		goto failure;

	n--;
	uc &= 0x3F >> n;

	for (;;) {
		uc = UTF8_ACCUMULATE(uc, c);
		if (--n == 0)
			break;
		c = *++s;

		/* Any further bytes must be in the range 0x80...0xBF. */
		if (0x80 != (0xC0 & c))
			goto failure;
	}

	/* Check for BOMs (*FFFE) and invalid codepoints (*FFFF) */
	if (0xFFFE == (0xFFFE & uc))
		goto failure;

	return uc;

failure:
	*retlen = 0;
	return 0;
}

/**
 * This routine is the same as utf8_decode_char() but it is more specialized
 * and is aimed at being fast.  Use it when you don't need warnings and you
 * don't know the length of the string you're reading from.
 *
 * @returns the character value of the first character in the string `s',
 * which is assumed to be in UTF-8 encoding, and ending with a NUL byte.
 * `retlen' will be set to the length, in bytes, of that character.
 *
 * If `s' does not point to a well-formed UTF-8 character, `retlen' is
 * set to 0 and the function returns 0.
 */
uint32 G_HOT
utf8_decode_char_fast(const char *s, uint *retlen)
{
	uint32 uc = (uchar) *s;
	uint n = utf8_skip(uc);

	/*
	 * utf8_skip() returns zero for an invalid initial byte.
	 * It also rejects surrogates (U+D800..U+DFFF) implicitely.
	 */

	*retlen = n;

	if G_UNLIKELY(0 == n)
		return 0;
	else if (1 == n)
		return uc;
	else
		return utf8_decode_large_char_fast(s + 1, uc, retlen);
}

/**
 * Decodes a single UTF-8 character.
 *
 * The string is not necessarily NUL-terminated, so the remaining length
 * of the string is passed.
 *
 * @returns the character value of the first character in the string `s',
 * which is assumed to be in UTF-8 encoding.
 * `retlen' will be set to the length, in bytes, of that character.
 *
 * If `s' does not point to a well-formed UTF-8 character or if the string
 * is too short to hold the character entirely, `retlen' is set to 0 and the
 * function returns 0.
 */
uint32
utf8_decode_char_buffer(const char *s, size_t len, uint *retlen)
{
	uint32 uc;
	uint n;

	if (0 == len)
		goto failure;

	/*
	 * utf8_skip() returns zero for an invalid initial byte.
	 * It also rejects surrogates (U+D800..U+DFFF) implicitely.
	 */

	uc = (uchar) *s;
	n = utf8_skip(uc);
	*retlen = n;

	if G_UNLIKELY(0 == n)
		return 0;
	else if (1 == n)
		return uc;
	else if G_UNLIKELY(len < n)
		goto failure;
	else
		return utf8_decode_large_char_fast(s + 1, uc, retlen);

failure:
	*retlen = 0;
	return 0;
}

/**
 * Are the first bytes of string `s' forming a valid UTF-8 character?
 *
 * @param s a NUL-terminated string or at minimum a buffer with 4 bytes.
 * @return amount of bytes used to encode that character, or 0 if invalid.
 */
uint
utf8_char_len(const char *s)
{
	uint32 uc = (uchar) *s;

	if (UTF8_IS_ASCII(uc))
		return 1;
	else {
		uint clen = utf8_skip(uc);

		(void) utf8_decode_large_char_fast(s + 1, uc, &clen);
		return clen;
	}
}

/**
 * Computes the length of the UTF-8 character, ignoring invalid encodings.
 *
 * This is suitable in operations where we're not going to alter the encoding,
 * for instance during copy.
 */
static inline uint G_PURE
utf8_char_len_probe(const char *s)
{
	uint32 uc = (uchar) *s;

	if (UTF8_IS_ASCII(uc))
		return 1;

	uc &= 0xF0;
	if (uc < 0xE0)
		return 2;

	return 0xE0 == uc ? 3 : 4;
}

/**
 * Determine whether a string is UTF-8 encoded.
 *
 * @param src a NUL-terminated string.
 * @return FALSE if there are any non-UTF-8 characters before the
 *         terminating NUL, otherwise TRUE.
 */
bool
utf8_is_valid_string(const char *src)
{
	const char *s;
	uint clen;

	for (s = src; '\0' != *s; s += clen) {
		if (0 == (clen = utf8_char_len(s)))
			return FALSE;
	}

	return TRUE;
}

/**
 * @return	TRUE if the first `len' bytes of the given string
 *			`s' form valid a UTF-8 string, FALSE otherwise.
 */
bool
utf8_is_valid_data(const char *src, size_t len)
{
	g_assert(src);

	while (len > 0) {
		size_t clen;

		clen = utf8_skip(*src);
		if (clen > len || 0 == utf8_char_len(src))
			break;
		len -= clen;
		src += clen;
	}
	return 0 == len;
}

/**
 * Slowly count the amount of UTF-8 codepoints in the string, validating
 * each codepoint for valid encoding.
 *
 * @param src		a NUL-terminated string buffer
 *
 * @return the amount of Unicode characters, -1 if we found an invalid UTF-8
 * encoding.
 */
size_t
utf8_char_count(const char *src)
{
	const char *s;
	uint clen;
	size_t n;

	for (s = src, n = 0; '\0' != *s; s += clen, n++)
		if (0 == (clen = utf8_char_len(s)))
			return (size_t) -1;

	return n;
}

/**
 * Slowly count the amount of UTF-8 codepoints in the string, validating
 * each codepoint for valid encoding.
 *
 * @param src		a string buffer (not necessarily NUL-terminated)
 * @param len		length of buffer
 *
 * @return the amount of Unicode characters, -1 if we found an invalid UTF-8
 * encoding.
 */
size_t
utf8_data_char_count(const char *src, size_t len)
{
	const char *s;
	size_t rlen;
	uint clen;
	size_t n;

	for (
		s = src, n = 0, rlen = len;
		size_is_positive(rlen) && (clen = utf8_skip(*s)) <= rlen;
		s += clen, n++, rlen -= clen
	)
		if (0 == (utf8_char_len(s)))
			return (size_t) -1;

	return n;
}

#define ONEMASK ((size_t) (-1) / 0xff)	/* 0x01010101 on 32-bit machine */

/**
 * Quickly compute the amount of UTF-8 codepoints in the string, without
 * validating that the string is a valid UTF-8 one.
 *
 * @param src		a NUL-terminated string buffer, assumed valid UTF-8
 *
 * @return the amount of Unicode characters in the string.
 *
 * This code was designed by Colin Percival for speed.
 * See http://www.daemonology.net/blog/2008-06-05-faster-utf8-strlen.html
 */
size_t
utf8_strlen(const char *str)
{
	const char * s;
	size_t count = 0;	/* Bytes which are NOT the first byte of a character */
	size_t u;
	unsigned char b;

	/*
	 * Handle any initial misaligned bytes.
	 */

	for (s = str; pointer_to_ulong(s) & (sizeof(size_t) - 1); s++) {
		b = *s;

		if (b == '\0')
			goto done;		/* Exit if we hit a zero byte. */

		/* Is this byte NOT the first byte of a character? */
		count += (b >> 7) & ((~b) >> 6);
	}

	/*
	 * Handle complete blocks.
	 *
	 * This may read more byte than are present in the string, should the
	 * trailing NUL byte be in the middle of a block.
	 *
	 * However, this is safe because we cannot cross any page boundary
	 * by doing so, hence we cannot incur a memory fault.  This relies
	 * on the fact that the initial string is NUL-terminated, of course.
	 */

	for (; ; s += sizeof(size_t)) {
		G_PREFETCH_R(&s[UTF8_CPU_CACHELINE]); /* Prefetch a cacheline ahead */

		u = *(size_t *) s;		/* Grab 4 or 8 bytes of UTF-8 data */

		if ((u - ONEMASK) & (~u) & (ONEMASK * 0x80))
			break;				/* Exit loop if there are any zero bytes */

		/* Count bytes which are NOT the first byte of a character. */
		u = ((u & (ONEMASK * 0x80)) >> 7) & ((~u) >> 6);
		count += (u * ONEMASK) >> ((sizeof(size_t) - 1) * 8);
	}

	/*
	 * Take care of any left-over bytes.
	 */

	for (; ; s++) {
		b = *s;

		if (b == '\0')
			break;			/* Exit if we hit a zero byte */

		/* Is this byte NOT the first byte of a character? */
		count += (b >> 7) & ((~b) >> 6);
	}

done:
	return (s - str) - count;
}

/**
 * Works exactly like strlcpy() but preserves a valid UTF-8 encoding, if
 * the string has to be truncated.
 *
 * @param dst the target buffer to copy the string to.
 * @param src the source buffer to copy the string from.
 * @param dst_size the number of bytes ``dst'' can hold.
 */
size_t
utf8_strlcpy(char *dst, const char *src, size_t dst_size)
{
	char *d = dst;
	const char *s = src;

	g_assert(NULL != dst);
	g_assert(NULL != src);

	if (dst_size-- > 0) {
		while ('\0' != *s) {
			size_t clen;

			clen = utf8_char_len_probe(s);
			if G_UNLIKELY(clen > dst_size)
				break;

			if (clen == 1) {
				*d++ = *s++;
				dst_size--;
			} else {
				dst_size -= clen;
				while (clen--)
					*d++ = *s++;
			}
		}
		*d = '\0';
	}
 	while (*s)
		s++;
	return s - src;
}

/**
 * Works similar to strlcpy() but preserves a valid UTF-8 encoding, if
 * the string has to be truncated and copies at maximum ``max_chars''
 * UTF-8 characters. Thus, it's more useful for visual truncation in
 * contrast to just making it sure it fits into a certain buffer.
 *
 * @param dst the target buffer to copy the string to.
 * @param dst_size the number of bytes ``dst'' can hold.
 * @param src the source buffer to copy the string from.
 * @param max_chars the maximum amount of characters to copy.
 */
size_t
utf8_strcpy_max(char *dst, size_t dst_size, const char *src, size_t max_chars)
{
	char *d = dst;
	const char *s = src;

	g_assert(NULL != dst);
	g_assert(NULL != src);

	if (dst_size-- > 0) {
		while ('\0' != *s && max_chars > 0) {
			size_t clen;

			clen = utf8_char_len_probe(s);
			if G_UNLIKELY(clen > dst_size)
				break;
			max_chars--;

			if (clen == 1) {
				*d++ = *s++;
				dst_size--;
			} else {
				dst_size -= clen;
				while (clen--)
					*d++ = *s++;
			}
		}
		*d = '\0';
	}
 	while (*s)
		s++;
	return s - src;
}

/**
 * Encodes a single UTF-32 character as UTF-16 big-endian into a buffer.
 * See also RFC 2781.
 *
 * @param uc the unicode character to encode.
 * @param dst the destination buffer. MUST BE at least 4 bytes long.
 * @returns 0 if the unicode character is invalid. Otherwise, the
 *          amount of UTF-16 characters is returned i.e., 1 or 2.
 */
static unsigned NON_NULL_PARAM((2))
utf16_encode_char(uint32 uc, uint16 *dst)
{
	if (uc < 0xFFFF) {
		dst[0] = uc;
		dst[1] = 0;
		return 1;
	} else if (uc > 0xFFFFU && uc <= 0x10FFFFUL) {
		uc -= 0x10000;
		dst[0] = (uc >> 10) | UNI_SURROGATE_FIRST;
		dst[1] = (uc & 0x3ff) | UNI_SURROGATE_SECOND;
		return 2;
	} else {
		return 0;
	}
}

/**
 * @param uc the unicode character to encode.
 * @returns 0 if the unicode codepoint is invalid. Otherwise the
 *          length of the UTF-8 character is returned.
 */
unsigned
utf16_encoded_char_len(uint32 uc)
{
	if (uc < 0xFFFF) {
		return 1;
	} else if (uc > 0xFFFFU && uc <= 0x10FFFFUL) {
		return 2;
	} else {
		return 0;
	}
}

/**
 * Decodes a single UTF-16 character (big-endian representation).
 *
 * The string is not necessarily NUL-terminated, so the remaining length
 * of the string is passed.
 *
 * @returns the character value of the first character in the string `s',
 * which is assumed to be in UTF-16 encoding.
 * `retlen' will be set to the length, in bytes, of that character.
 *
 * If `s' does not point to a well-formed UTF-16 character or is too short
 * to contain the whole character, `retlen' is set to 0 and the function
 * returns 0.
 */
uint32
utf16_be_decode_char_buffer(const char *s, size_t len, uint *retlen)
{
	uchar c;
	uint16 first;

	if (len < 2)
		goto malformed;

	c = *s++;

	if (0 == c)
		goto malformed;

	first = (uint16) c << 8;
	c = *s++;
	if (0 == c)
		goto malformed;
	first |= (uint16) c;

	len -= 2;

	if ((first & 0xfc00) == UNI_SURROGATE_FIRST) {
		uint16 second;
		uint32 uc;

		if (len < 2)
			goto single_char;

		c = *s++;
		if (0 == c)
			goto single_char;
		second = (uint16) c << 8;
		c = *s++;
		if (0 == c)
			goto single_char;
		second |= (uint16) c;

		if ((second & 0xfc00) != UNI_SURROGATE_SECOND)
			goto single_char;

		uc = ((uint32) (first & 0x3ff) << 10) | (uint32) (second & 0x3ff);

		*retlen = 4;
		return uc + 0x10000;
	}

single_char:
		*retlen = 2;
		return first;

malformed:
	*retlen = 0;
	return 0;
}

/**
 * Decodes a single UTF-16 character (little-endian representation).
 *
 * The string is not necessarily NUL-terminated, so the remaining length
 * of the string is passed.
 *
 * @returns the character value of the first character in the string `s',
 * which is assumed to be in UTF-16 encoding.
 * `retlen' will be set to the length, in bytes, of that character.
 *
 * If `s' does not point to a well-formed UTF-16 character or is too short
 * to contain the whole character, `retlen' is set to 0 and the function
 * returns 0.
 */
uint32
utf16_le_decode_char_buffer(const char *s, size_t len, uint *retlen)
{
	uchar c;
	uint16 first;

	if (len < 2)
		goto malformed;

	c = *s++;

	if (0 == c)
		goto malformed;

	first = (uint16) c;
	c = *s++;
	if (0 == c)
		goto malformed;
	first |= (uint16) c << 8;

	len -= 2;

	if ((first & 0xFC00) == UNI_SURROGATE_FIRST) {
		uint16 second;
		uint32 uc;

		if (len < 2)
			goto single_char;

		c = *s++;
		if (0 == c)
			goto single_char;
		second = (uint16) c;
		c = *s++;
		if (0 == c)
			goto single_char;
		second |= (uint16) c << 8;

		if ((second & 0xFC00) != UNI_SURROGATE_SECOND)
			goto single_char;

		uc = ((uint32) (first & 0x3ff) << 10) | (uint32) (second & 0x3ff);

		*retlen = 4;
		return uc + 0x10000;
	}

single_char:
	*retlen = 2;
	return first;

malformed:
	*retlen = 0;
	return 0;
}

/**
 * Decodes a single UTF-32 character (big-endian representation).
 *
 * The string is not necessarily NUL-terminated, so the remaining length
 * of the string is passed.
 *
 * @returns the character value of the first character in the string `s',
 * which is assumed to be in UTF-32 encoding.
 * `retlen' will be set to the length, in bytes, of that character.
 *
 * If `s' does not point to a well-formed UTF-32 character or is too short
 * to contain the whole character, `retlen' is set to 0 and the function
 * returns 0.
 */
uint32
utf32_be_decode_char_buffer(const char *s, size_t len, uint *retlen)
{
	uint32 uc;

	if (len < 4)
		goto malformed;

	uc = peek_be32(s);
	if (utf32_bad_codepoint(uc))
		goto malformed;

	*retlen = 4;
	return uc;

malformed:
	*retlen = 0;
	return 0;
}

/**
 * Decodes a single UTF-32 character (little-endian representation).
 *
 * The string is not necessarily NUL-terminated, so the remaining length
 * of the string is passed.
 *
 * @returns the character value of the first character in the string `s',
 * which is assumed to be in UTF-32 encoding.
 * `retlen' will be set to the length, in bytes, of that character.
 *
 * If `s' does not point to a well-formed UTF-32 character or is too short
 * to contain the whole character, `retlen' is set to 0 and the function
 * returns 0.
 */
uint32
utf32_le_decode_char_buffer(const char *s, size_t len, uint *retlen)
{
	uint32 uc;

	if (len < 4)
		goto malformed;

	uc = peek_le32(s);
	if (utf32_bad_codepoint(uc))
		goto malformed;

	*retlen = 4;
	return uc;

malformed:
	*retlen = 0;
	return 0;
}

/* List of known codesets. The first word of each string is the alias to be
 * returned. The words are seperated by whitespaces.
 */
static const char *codesets[] = {
 "ASCII ISO_646.IRV:1983 646 C US-ASCII la_LN.ASCII lt_LN.ASCII ANSI_X3.4-1968",
 "BIG5 big5 big5 zh_TW.BIG5 zh_TW.Big5",
 "CP1046 IBM-1046",
 "CP1124 IBM-1124",
 "CP1129 IBM-1129",
 "CP1252 IBM-1252",
 "CP437 en_NZ en_US",
 "CP775 lt lt_LT lv lv_LV",
 "CP850 IBM-850 cp850 ca ca_ES de de_AT de_CH de_DE en en_AU en_CA en_GB "
	"en_ZA es es_AR es_BO es_CL es_CO es_CR es_CU es_DO es_EC es_ES es_GT "
	"es_HN es_MX es_NI es_PA es_PY es_PE es_SV es_UY es_VE et et_EE eu eu_ES "
	"fi fi_FI fr fr_BE fr_CA fr_CH fr_FR ga ga_IE gd gd_GB gl gl_ES id id_ID "
	"it it_CH it_IT nl nl_BE nl_NL pt pt_BR pt_PT sv sv_SE mt mt_MT eo eo_EO",
 "CP852 cs cs_CZ hr hr_HR hu hu_HU pl pl_PL ro ro_RO sk sk_SK sl sl_SI "
	"sq sq_AL sr sr_YU",
 "CP856 IBM-856",
 "CP857 tr tr_TR",
 "CP861 is is_IS",
 "CP862 he he_IL",
 "CP864 ar ar_AE ar_DZ ar_EG ar_IQ ar_IR ar_JO ar_KW ar_MA ar_OM ar_QA "
	"ar_SA ar_SY",
 "CP865 da da_DK nb nb_NO nn nn_NO no no_NO",
 "CP866 ru_RU.CP866 ru_SU.CP866 be be_BE bg bg_BG mk mk_MK ru ru_RU ",
 "CP869 el el_GR",
 "CP874 th th_TH",
 "CP922 IBM-922",
 "CP932 IBM-932 ja ja_JP",
 "CP943 IBM-943",
 "CP949 KSC5601 kr kr_KR",
 "CP950 zh_TW",
 "DEC-HANYU dechanyu",
 "DEC-KANJI deckanji",
 "EUC-JP IBM-eucJP eucJP eucJP sdeckanji ja_JP.EUC",
 "EUC-KR IBM-eucKR eucKR eucKR deckorean 5601 ko_KR.EUC",
 "EUC-TW IBM-eucTW eucTW eucTW cns11643",
 "GB2312 IBM-eucCN hp15CN eucCN dechanzi gb2312 zh_CN.EUC",
 "GBK zh_CN",
 "HP-ARABIC8 arabic8",
 "HP-GREEK8 greek8",
 "HP-HEBREW8 hebrew8",
 "HP-KANA8 kana8",
 "HP-ROMAN8 roman8 ",
 "HP-TURKISH8 turkish8 ",
 "ISO-8859-1 ISO8859-1 iso88591 da_DK.ISO_8859-1 de_AT.ISO_8859-1 "
	"de_CH.ISO_8859-1 de_DE.ISO_8859-1 en_AU.ISO_8859-1 en_CA.ISO_8859-1 "
	"en_GB.ISO_8859-1 en_US.ISO_8859-1 es_ES.ISO_8859-1 fi_FI.ISO_8859-1 "
	"fr_BE.ISO_8859-1 fr_CA.ISO_8859-1 fr_CH.ISO_8859-1 fr_FR.ISO_8859-1 "
	"is_IS.ISO_8859-1 it_CH.ISO_8859-1 it_IT.ISO_8859-1 la_LN.ISO_8859-1 "
	"lt_LN.ISO_8859-1 nl_BE.ISO_8859-1 nl_NL.ISO_8859-1 no_NO.ISO_8859-1 "
	"pt_PT.ISO_8859-1 sv_SE.ISO_8859-1",
 "ISO-8859-13 IBM-921",
 "ISO-8859-14 ISO_8859-14 ISO_8859-14:1998 iso-ir-199 latin8 iso-celtic l8",
 "ISO-8859-15 ISO8859-15 iso885915 da_DK.DIS_8859-15 de_AT.DIS_8859-15 "
	"de_CH.DIS_8859-15 de_DE.DIS_8859-15 en_AU.DIS_8859-15 en_CA.DIS_8859-15 "
	"en_GB.DIS_8859-15 en_US.DIS_8859-15 es_ES.DIS_8859-15 fi_FI.DIS_8859-15 "
	"fr_BE.DIS_8859-15 fr_CA.DIS_8859-15 fr_CH.DIS_8859-15 fr_FR.DIS_8859-15 "
	"is_IS.DIS_8859-15 it_CH.DIS_8859-15 it_IT.DIS_8859-15 la_LN.DIS_8859-15 "
	"lt_LN.DIS_8859-15 nl_BE.DIS_8859-15 nl_NL.DIS_8859-15 no_NO.DIS_8859-15 "
	"pt_PT.DIS_8859-15 sv_SE.DIS_8859-15",
 "ISO-8859-2 ISO8859-2 iso88592 cs_CZ.ISO_8859-2 hr_HR.ISO_8859-2 "
	"hu_HU.ISO_8859-2 la_LN.ISO_8859-2 lt_LN.ISO_8859-2 pl_PL.ISO_8859-2 "
	"sl_SI.ISO_8859-2",
 "ISO-8859-4 ISO8859-4 la_LN.ISO_8859-4 lt_LT.ISO_8859-4",
 "ISO-8859-5 ISO8859-5 iso88595 ru_RU.ISO_8859-5 ru_SU.ISO_8859-5",
 "ISO-8859-6 ISO8859-6 iso88596",
 "ISO-8859-7 ISO8859-7 iso88597",
 "ISO-8859-8 ISO8859-8 iso88598",
 "ISO-8859-9 ISO8859-9 iso88599",
 "KOI8-R koi8-r ru_RU.KOI8-R ru_SU.KOI8-R",
 "KOI8-U uk_UA.KOI8-U",
 "SHIFT_JIS SJIS PCK ja_JP.SJIS ja_JP.Shift_JIS",
 "TIS-620 tis620 TACTIS TIS620.2533",
 "UTF-8 utf8 *",
 NULL
};

/**
 * @returns a string representing the specified charset as an alias which is
 * understood by GNU iconv. The returned pointer points to a static buffer.
 */
const char *
get_iconv_charset_alias(const char *cs)
{
	const char *start = codesets[0], *first_end = NULL;
	int i = 0;

	if (NULL == cs || '\0' == *cs)
		return NULL;

	while (NULL != codesets[i]) {
		static char buf[64];
		const char *end;
		size_t len;

		end = strchr(start, ' ');
		if (NULL == end)
			end = strchr(start, '\0');
		if (NULL == first_end)
			first_end = end;

 		len = end - start;
		if (len > 0 && is_strcaseprefix(start, cs)) {
			len = first_end - codesets[i] + 1;
			g_strlcpy(buf, codesets[i], MIN(len, sizeof(buf)));
			return buf;
		}
		if ('\0' == *end) {
			first_end = NULL;
			start = codesets[++i];
		} else
			start = end + 1;

	}
	return NULL;
}

/**
 * NOTE:	The internal variable "charset" can be used to override
 * 			the initially detected character set name.
 *
 * @return the name of current locale's character set.
 */
const char *
locale_get_charset(void)
{
	static bool initialized;
	static const char *cs;

	if (!initialized) {
#if defined(USE_GLIB2)
		g_get_charset(&cs);
#else /* !USE_GLIB2 */
#if defined(HAS_LOCALE_CHARSET)
		cs = locale_charset();
#else /* !I_LIBCHARSET */
		cs = get_iconv_charset_alias(nl_langinfo(CODESET));
#endif /* I_LIBCHARSET */
#endif /* USE_GLIB2 */

		if (cs == NULL) {
			/* Default locale codeset */
			cs = "ISO-8859-1";
			g_warning("%s(): using default codeset %s as fallback",
				G_STRFUNC, cs);
		}

		cs = h_strdup(cs);
		initialized = TRUE;
	}

	return charset ? charset : cs;
}

/**
 *  Determine the current language.
 *
 *	@return A two-letter ISO 639 of the language currently used for
 *			messages.
 */
const char *
locale_get_language(void)
{
	/**
	 * TRANSLATORS: Put the two-letter ISO 639 code here.
	 */
	return Q_("locale_get_language|en");
}

static struct conv_to_utf8 *
conv_to_utf8_new(const char *cs)
{
	struct conv_to_utf8 *t;

	WALLOC(t);
	t->magic = CONV_TO_UTF8_MAGIC;
	t->cd = (iconv_t) -1;
	t->name = atom_str_get(cs);
	t->is_utf8 = 0 == strcmp(cs, "UTF-8");
	t->is_ascii = 0 == strcmp(cs, "ASCII");
	t->is_iso8859 = NULL != is_strprefix(cs, "ISO-8859-");

	hikset_insert_key(charset2conv_to_utf8, &t->name);

	return t;
}

static void
conv_to_utf8_free(struct conv_to_utf8 *cu)
{
	conv_to_utf8_check(cu);

	atom_str_free_null(&cu->name);
	if (cu->cd != (iconv_t) -1) {
		iconv_close(cu->cd);
		cu->cd = (iconv_t) -1;
	}
	cu->magic = 0;
	WFREE(cu);
}

/**
 * Initialize "to UTF-8" convertors.
 */
static void
conv_to_utf8_init(struct conv_to_utf8 *cu)
{
	conv_to_utf8_check(cu);

	if (0 == strcmp("@locale", cu->name) || 0 == strcmp(charset, cu->name))
		cu->cd = cd_locale_to_utf8;
	else if (UTF8_CD_INVALID != utf8_name_to_cd(cu->name))
		cu->cd = utf8_cd_get(utf8_name_to_cd(cu->name));
	else if ((iconv_t) -1 == (cu->cd = iconv_open("UTF-8", cu->name)))
			g_warning("iconv_open(\"UTF-8\", \"%s\") failed.", cu->name);
}

/**
 * Get iconv() descriptor to convert from given charset name to UTF-8.
 *
 * @param cs	normalized character set name
 *
 * @return iconv_t to translate given charset name into UTF-8, -1 on error.
 */
static iconv_t
conv_to_utf8_cd_get(const char *cs)
{
	struct conv_to_utf8 *cu;

	cu = hikset_lookup(charset2conv_to_utf8, cs);
	if (NULL == cu)
		cu = conv_to_utf8_new(cs);

	conv_to_utf8_check(cu);

	if ((iconv_t) -1 == cu->cd)
		conv_to_utf8_init(cu);

	return cu->cd;
}

/**
 * Emulate GLib 2.x behaviour and select the appropriate character set
 * for filenames.
 *
 * @param locale the name of the current locale character set.
 * @return	a list of newly allocated strings holding the names of the
 * 			used character sets. The first is the one that should be
 *			used when creating files.
 */
static pslist_t * G_COLD
get_filename_charsets(const char *locale)
{
	const char *s, *next;
	bool has_locale = FALSE, has_utf8 = FALSE;
	pslist_t *sl = NULL;

	g_assert(locale);

	for (s = getenv("G_FILENAME_ENCODING"); s && '\0' != *s; s = next) {
		const char *ep;

		/* Skip empty elements and leading blanks */
		while (',' == *s || is_ascii_blank(*s))
			++s;

		next = strchr(s, ',');
		ep = next ? next : strchr(s, '\0');

		/* Skip backwards over trailing blanks */
		while (ep != s && is_ascii_blank(*(ep - 1)))
			--ep;

		if (ep != s) {
			const char *cs;

			if (is_strcaseprefix(s, "@locale") == ep) {
				cs = locale;
			} else {
				char *q = h_strndup(s, ep - s);
				cs = get_iconv_charset_alias(q);
				HFREE_NULL(q);
			}

			/*
			 * If the locale or UTF-8 was already listed, skip it. This way
			 * using G_FILENAME_ENCODING="UTF-8,@locale,ISO-8859-1" has no
			 * negative effect on performance if @locale is UTF-8 or
			 * ISO-8859-1.
			 */
			if (cs && 0 == strcmp(cs, "UTF-8")) {
				if (has_utf8)
					cs = NULL;
				has_utf8 = TRUE;
			}
			if (cs && 0 == strcmp(cs, locale)) {
				if (has_locale)
					cs = NULL;
				has_locale = TRUE;
			}

			if (cs)
				sl = pslist_prepend(sl, conv_to_utf8_new(cs));
		}
	}


	/* If UTF-8 wasn't in the list, add it as penultimate (or actually first)
	 * option. */
	if (!has_utf8)
		sl = pslist_prepend(sl, conv_to_utf8_new("UTF-8"));

	/* Always add the locale charset as last resort if not already listed. */
	if (!has_locale && 0 != strcmp("UTF-8", locale))
		sl = pslist_prepend(sl, conv_to_utf8_new(locale));

	return pslist_reverse(sl);
}

static void
textdomain_init(const char *codeset)
{
#ifdef ENABLE_NLS
	{
		const char *nlspath = get_folder_path(NLS_PATH);
		bindtextdomain(PACKAGE, nlspath);
	}

#ifdef HAS_BIND_TEXTDOMAIN_CODESET

#ifdef USE_GLIB2
	codeset = "UTF-8";
#endif /* USE_GLIB2*/

	bind_textdomain_codeset(PACKAGE, codeset);

#endif /* HAS_BIND_TEXTDOMAIN_CODESET */

	textdomain(PACKAGE);

#else /* !NLS */
	(void) codeset;
#endif /* NLS */
}

static void
locale_init_show_results(void)
{
	const pslist_t *sl = sl_filename_charsets;

	g_info("language code: \"%s\"", locale_get_language());
	g_info("using locale character set \"%s\"", charset);
	g_info("primary filename character set \"%s\"",
		primary_filename_charset());

	while (NULL != (sl = pslist_next(sl))) {
		const struct conv_to_utf8 *t = pslist_data(sl);

		conv_to_utf8_check(t);
		g_info("additional filename character set \"%s\"", t->name);
	}
}

static void G_COLD
conversion_init(void)
{
	const char *pfcs = primary_filename_charset();
	iconv_t cd_from_utf8;

	g_assert(charset);
	g_assert(pfcs);

	/*
	 * Don't use iconv() for UTF-8 -> UTF-8 conversion, it's
	 * pointless and apparently some implementations don't filter
	 * invalid codepoints beyond U+10FFFF.
	 */

	if (!locale_is_utf8()) {
		/* locale -> UTF-8 */
		if (UTF8_CD_INVALID != utf8_name_to_cd(charset))
			cd_locale_to_utf8 = utf8_cd_get(utf8_name_to_cd(charset));

		if ((iconv_t) -1 == cd_locale_to_utf8) {
			cd_locale_to_utf8 = iconv_open("UTF-8", charset);
			if ((iconv_t) -1 == cd_locale_to_utf8)
				g_warning("iconv_open(\"UTF-8\", \"%s\") failed.", charset);
		}

		/* UTF-8 -> locale */
		if ((iconv_t) -1 == (cd_utf8_to_locale = iconv_open(charset, "UTF-8")))
			g_warning("iconv_open(\"%s\", \"UTF-8\") failed.", charset);
	}

	/* Initialize UTF-8 -> primary filename charset conversion */

	/*
	 * We don't need cd_utf8_to_filename if the filename character set
	 * is ASCII or UTF-8. In the former case we fall back to ascii_enforce()
	 * and in the latter conversion is nonsense.
	 */
	if (primary_filename_charset_is_utf8() || 0 == strcmp(pfcs, "ASCII")) {
		cd_from_utf8 = (iconv_t) -1;
	} else if (UTF8_CD_INVALID != utf8_name_to_cd(pfcs)) {
		if ((iconv_t) -1 == (cd_from_utf8 = iconv_open(pfcs, "UTF-8")))
			g_warning("iconv_open(\"%s\", \"UTF-8\") failed.", pfcs);
	} else if (0 == strcmp(charset, pfcs)) {
		cd_from_utf8 = cd_utf8_to_locale;
	} else {
		if ((iconv_t) -1 == (cd_from_utf8 = iconv_open(pfcs, "UTF-8")))
			g_warning("iconv_open(\"%s\", \"UTF-8\") failed.", pfcs);
	}

	cd_utf8_to_filename = cd_from_utf8;

	cd_utf8_to_iso8859_1 = iconv_open("ISO-8859-1", "UTF-8");
	if ((iconv_t) -1 == cd_utf8_to_iso8859_1) {
		g_warning("iconv_open(\"%s\", \"UTF-8\") failed.", "ISO-8859-1");
	}

	/* Initialize filename charsets -> UTF-8 conversion */

	PSLIST_FOREACH_CALL(sl_filename_charsets, conv_to_utf8_init);
}

static void
conversion_free_kv(void *value, void *u_data)
{
	(void) u_data;

	conv_to_utf8_free(value);
}

static void
conversion_close(void)
{
	hikset_foreach(charset2conv_to_utf8, conversion_free_kv, NULL);
	hikset_free_null(&charset2conv_to_utf8);
}

void G_COLD
locale_init(void)
{
	static const char * const latin_sets[] = {
		"ASCII",
		"ISO-8859-1",
		"ISO-8859-15",
		"CP1252",
		"MacRoman",
		"CP437",
		"CP775",
		"CP850",
		"CP852",
		"CP865",
		"HP-ROMAN8",
		"ISO-8859-2",
		"ISO-8859-4",
		"ISO-8859-14",
	};
	uint i;

	/* Must not be called multiple times */
	g_return_if_fail(!locale_init_passed);

	BINARY_ARRAY_SORTED(utf32_nfkd_lut,
		struct utf32_nfkd, c & ~UTF32_F_MASK, CMP, uint32_to_string);
	BINARY_ARRAY_SORTED(utf32_comb_class_lut,
		struct utf32_comb_class, uc, CMP, uint32_to_string);
	BINARY_ARRAY_SORTED(utf32_general_category_lut,
		struct utf32_general_category, uc, CMP, uint32_to_string);

#ifdef MINGW32
	setlocale(LC_ALL, g_win32_getlocale());
#else
	setlocale(LC_ALL, "");
#endif
	charset = deconstify_pointer(locale_get_charset());

	/*
	 * If the character set could not be properly detected, use ASCII as
	 * default for the filename character set, even though we use ISO-8859-1 as
	 * default locale character set.
	 *
	 * Since get_filename_charsets() can create conv_to_utf8 objects, we
	 * need to create the mapping table storing all these objects by name,
	 * not waiting for the conversion_init() call which comes later and will
	 * peruse the list we build here in sl_filename_charsets.
	 */

	charset2conv_to_utf8 = hikset_create(
		offsetof(struct conv_to_utf8, name), HASH_KEY_STRING, 0);
	sl_filename_charsets = get_filename_charsets(charset ? charset : "ASCII");
	g_assert(sl_filename_charsets);
	g_assert(sl_filename_charsets->data);

	textdomain_init(charset);

	for (i = 0; i < N_ITEMS(latin_sets); i++) {
		if (0 == ascii_strcasecmp(charset, latin_sets[i])) {
			latin_locale = TRUE;
			break;
		}
	}

#if 0  /* xxxUSE_ICU */
	{
		UErrorCode errorCode = U_ZERO_ERROR;

		/* set up the locale converter */
		conv_icu_locale = ucnv_open(charset, &errorCode);
		if (U_FAILURE(errorCode)) {
			g_warning("ucnv_open for locale failed with %d", errorCode);
		} else {

			/* set up the UTF-8 converter */
			conv_icu_utf8 = ucnv_open("utf8", &errorCode);
			if (U_FAILURE(errorCode)) {
				g_warning("ucnv_open for utf-8 failed with %d", errorCode);
			} else {
				/* Initialization succeeded, thus enable using of ICU */
				use_icu = TRUE;
			}
		}
	}
#endif

	conversion_init();
	unicode_compose_init();

#if 0 && !defined(OFFICIAL_BUILD)
	utf8_regression_checks();
#endif	/* !OFFICIAL_BUILD */

	locale_init_passed = TRUE;
	locale_init_show_results();
}

/**
 * Hashtable iteration callback to free lists from utf32_compose_roots.
 */
static void
compose_free_slist(const void *unused_key, void *value, void *unused_udata)
{
	pslist_t *sl = value;

	(void) unused_key;
	(void) unused_udata;

	pslist_free(sl);
}

/**
 * Called at shutdown time.
 */
void G_COLD
locale_close(void)
{
#if 0   /* xxxUSE_ICU */
	if (conv_icu_locale) {
	  ucnv_close(conv_icu_locale);
	  conv_icu_locale = NULL;
	}
	if (conv_icu_utf8) {
	  ucnv_close(conv_icu_utf8);
	  conv_icu_utf8 = NULL;
	}
#endif

	conversion_close();

	/*
	 * conv_to_utf8 structures from sl_filename_charsets have been inserted
	 * into the conversion hash table charset2conv_to_utf8 which is cleaned up
	 * by conversion_close().
	 *
	 * Hence we only need to free the list itself now.
	 */

	pslist_free_null(&sl_filename_charsets);
	HFREE_NULL(charset);

	htable_foreach(utf32_compose_roots, compose_free_slist, NULL);
	htable_free_null(&utf32_compose_roots);
}

/**
 * Converts the string in "src" into the buffer "dst" using the iconv
 * context "cd". If "dst_size" is too small, the resulting string will
 * be truncated. complete_iconv() returns the necessary buffer size.
 * IFF "dst_size" is zero, "dst" may be NULL.
 *
 * @note
 * NOTE: This assumes 8-bit (char-based) encodings.
 *
 * @param cd		an iconv context; if it is -1, NULL will be returned.
 * @param dst		the destination buffer; may be NULL IFF dst_size is zero.
 * @param dst_size	the size of the destination buffer in bytes.
 * @param src		the source string to convert.
 * @param src_len	the length of the source; if -1, computed as strlen(src)
 * @param abort_on_error If TRUE, the conversion is be aborted and zero
 *						 is returned on any error. Otherwise, if iconv()
 *						 returns EINVAL or EILSEQ an underscore is written
 *						 to the destination buffer as replacement character.
 *
 *
 * @return On success the size of the converting string including the
 *         trailing NUL. Otherwise, zero is returned.
 */
static size_t
complete_iconv(iconv_t cd, char *dst, const size_t dst_size, const char *src,
	size_t src_len, bool abort_on_error)
{
	size_t src_left, size = 0;

	g_assert(src);
	g_assert(0 == dst_size || dst);

	if ((iconv_t) -1 == cd) {
		if (common_dbg > 1)
			g_critical("%s(): bad cd", G_STRFUNC);
		errno = EBADF;
		goto error;
	}

	/* reset state */
	if ((size_t) -1 == iconv(cd, NULL, NULL, NULL, NULL)) {
		if (common_dbg > 1)
			g_warning("%s(): iconv() reset failed", G_STRFUNC);
		goto error;
	}

	src_left = (size_t) -1 == src_len ? strlen(src) : src_len;

	while (size_is_positive(src_left)) {
		char buf[4096];
		size_t ret, n_read, n_written;

		{
			size_t left0, left, buf_size = sizeof buf;
			char *buf_ptr = buf;

			/* To avoid E2BIG, feed only a part of src to iconv() */
			left0 = MIN(sizeof buf / 32, src_left);
			left = left0;

			ret = iconv(cd, cast_to_pointer(&src), &left, &buf_ptr, &buf_size);

			n_read = left0 - left;
			n_written = buf_ptr - buf;

			g_assert_log(size_is_non_negative(n_read),
				"n_read=%s", size_t_to_string(n_read));

			if (!size_is_non_negative(n_written)) {
				n_written = 0;
				g_assert((size_t) -1 == ret);	/* Only possible on errors */
			}

			g_assert(src_left >= n_read);

			src_left -= n_read;
		}

		size += n_written;
		if (dst_size > size) {
			dst = mempcpy(dst, buf, n_written);
		}

		if ((size_t) -1 == ret) {
			int e = errno;

			if (common_dbg > 1)
				g_warning("%s(): iconv() failed: %m", G_STRFUNC);

			g_assert(E2BIG != e);
			g_assert(EINVAL == e || EILSEQ == e);

			if (EINVAL == e) {
				/*
				 * An invalid character may be caused by feeding only a part of
				 * the input to iconv().
				 */
				if (n_read > 0 && src_left > 0)
					continue;
			}

			if (abort_on_error) {
				goto error;
			} else {
				size_t buf_size = sizeof buf;
				char *buf_ptr = buf;

				/* reset state; iconv() might store a shift reset sequence */
				if ((size_t) -1 == iconv(cd, NULL, NULL, &buf_ptr, &buf_size))
					goto error;

				n_written = buf_ptr - buf;

				g_assert_log(size_is_non_negative(n_written),
					"n_written=%s", size_t_to_string(n_written));

				size += n_written;
				if (dst_size > size) {
					dst = mempcpy(dst, buf, n_written);
				}
				size += 1;
				if (dst_size > size) {
					*dst++ = '_';
				}
				if (0 == n_read) {
					src++;
					src_left--;
				}
			}
		}
	}

	if (dst_size > size)
		*dst = '\0';

	return size + 1;	/* Includes terminating NUL */

error:
	return 0;
}

/**
 * Converts the string in "src" to "dst" using the iconv context "cd".
 * If complete_iconv() iconv fails, NULL is returned. Otherwise, the
 * converted string is returned. If "dst" was sufficiently large, "dst"
 * will be returned. If not, a newly allocated string is returned. In
 * the latter case complete_iconv() has to run twice. IFF dst_size is
 * zero "dst" won't be touched and may be NULL. For best performance
 * a small local buffer should be used as "dst" so that complete_iconv()
 * does not have to run twice, especially if the result is only used
 * temporarily and copying is not necessary.
 *
 * @param cd		an iconv context; if it is -1, NULL will be returned.
 * @param dst		the destination buffer; may be NULL IFF dst_size is zero.
 * @param dst_size 	the size of the dst buffer.
 * @param src		the source string to convert.
 * @param src_len	the length of src; if -1, computed with strlen(src)
 * @param abort_on_error If TRUE, NULL is returned if iconv() returns EINVAL
 *						 or EILSEQ during the conversion. Otherwise, an
 *						 underscore is used as replacement character and
 *						 conversion continues.
 *
 * @return On success the converted string, either "dst" or a newly
 *         allocated string. Returns NULL on failure.
 */
static char *
hyper_iconv(iconv_t cd, char *dst, size_t dst_size, const char *src,
	size_t src_len, bool abort_on_error)
{
	size_t size;

	/* Don't assert cd != -1, we allow this */
	g_assert(src);
	g_assert(0 == dst_size || dst);

	size = complete_iconv(cd, dst, dst_size, src, src_len, abort_on_error);
	if (0 == size) {
		dst = NULL;
	} else if (size > dst_size) {
		size_t n;

		dst = g_malloc(size);
		n = complete_iconv(cd, dst, size, src, src_len, abort_on_error);
		if (n != size) {
			g_error("size=%ld, n=%ld, src=\"%s\" dst=\"%s\"",
				(ulong) size, (ulong) n, src, dst);
		}
		g_assert(n == size);
	}
	return dst;
}

/**
 * Copies the NUL-terminated string ``src'' to ``dst'' replacing all invalid
 * characters (non-UTF-8) with underscores. ``src'' and ``dst'' may be identical
 * but must not overlap otherwise. If ``dst'' is to small, the resulting string
 * will be truncated but the UTF-8 encoding is preserved in any case.
 *
 * @param dst		the destination buffer.
 * @param size		the size in bytes of the destination buffer.
 * @param src		a NUL-terminated string (unless src_len != -1)
 * @param src_len	then length of src, -1 if src is NUL-terminated
 *
 * @return the length in bytes of resulting string assuming size was
 *         sufficiently large.
 */
static size_t
utf8_enforce_len(char *dst, size_t size, const char *src, size_t src_len)
{
	const char *s = src;
	char *d = dst;
	size_t remain = (size_t) -1 == src_len ? 1 : src_len;

	g_assert(0 == size || NULL != dst);
	g_assert(NULL != src);
	g_assert(size <= INT_MAX);
	/** TODO: Add overlap check */

#define LOOP_BODY										\
	if (src_len != (size_t) -1) {						\
		uint len = utf8_skip(*s);						\
		/* Break if whole character does not fit */		\
		if (len > remain)								\
			break;										\
		clen = utf8_char_len(s);						\
		g_assert(clen <= len);							\
		remain -= clen;									\
	} else {											\
		clen = utf8_char_len(s);						\
	}													\
														\
	if (MAX(1, clen) > size)							\
		break;											\
														\
	if (clen < 2) {										\
		*d++ = 0 == clen ? '_' : *s;					\
		s++;											\
		size--;											\
	} else {											\
		size -= clen;									\
		while (clen--)									\
			*d++ = *s++;								\
	}

	if (size-- > 0) {
		if (size > UTF8_CPU_CACHELINE) {
			/* Worth pre-fetching data */
			while (size_is_positive(remain) && '\0' != *s) {
				size_t clen;

				G_PREFETCH_R(&s[UTF8_CPU_CACHELINE]);
				G_PREFETCH_W(&d[UTF8_CPU_CACHELINE]);

				LOOP_BODY
			}
		} else {
			/* Not worth pre-fetching data */
			while (size_is_positive(remain) && '\0' != *s) {
				size_t clen;

				LOOP_BODY
			}
		}
		*d = '\0';
	}

#undef LOOP_BODY

 	while ('\0' != *s++)
		d++;

	return d - dst;
}

/**
 * Copies the NUL-terminated string ``src'' to ``dst'' replacing all invalid
 * characters (non-UTF-8) with underscores. ``src'' and ``dst'' may be identical
 * but must not overlap otherwise. If ``dst'' is to small, the resulting string
 * will be truncated but the UTF-8 encoding is preserved in any case.
 *
 * @param dst		the destination buffer.
 * @param size		the size in bytes of the destination buffer.
 * @param src		a NUL-terminated string (unless src_len != -1)
 * @param src_len	then length of src, -1 if src is NUL-terminated
 *
 * @return the length in bytes of resulting string assuming size was
 *         sufficiently large.
 */
size_t
utf8_enforce(char *dst, size_t size, const char *src)
{
	return utf8_enforce_len(dst, size, src, (size_t) -1);
}

/**
 * Copies the NUL-terminated string ``src'' to ``dst'' replacing all invalid
 * characters (non-ASCII) with underscores. ``src'' and ``dst'' may be identical
 * but must not overlap otherwise. If ``dst'' is to small, the resulting string
 * will be truncated.
 *
 * @param src a NUL-terminated string.
 * @param dst the destination buffer.
 * @param size the size in bytes of the destination buffer.
 * @return the length in bytes of resulting string assuming size was
 *         sufficiently large.
 */
size_t
ascii_enforce(char *dst, size_t size, const char *src)
{
	const char *s = src;
	char *d = dst;

	g_assert(0 == size || NULL != dst);
	g_assert(NULL != src);
	g_assert(size <= INT_MAX);
	/** TODO: Add overlap check */

	if (size > 0) {
		uchar c;

		for (/* NOTHING */; --size > 0 && '\0' != (c = *s); s++)
			*d++ = isascii(c) ? c : '_';

		*d = '\0';
	}

 	while ('\0' != *s++)
		d++;

	return d - dst;
}

/**
 * Applies utf8_enforce to the string "src" copying the
 * result into "dst" if "dst_size" is sufficiently large.
 *
 * @param dst		the destination buffer.
 * @param dst_size	the size in bytes of the destination buffer.
 * @param src		a NUL-terminated string (unless src_len != -1).
 * @param src_len	length of string; computed with strlen(src) if -1.
 *
 * @return If dst_size was sufficient dst is returned, otherwise
 *		   a newly allocated buffer.
 */
static char *
hyper_utf8_enforce(char *dst, size_t dst_size, const char *src, size_t src_len)
{
	size_t n;

	g_assert(src);
	g_assert(0 == dst_size || dst);

	n = utf8_enforce_len(dst, dst_size, src, src_len);
	if (n >= dst_size) {
		size_t size = 1 + n;

		dst = g_malloc(size);
		n = utf8_enforce_len(dst, size, src, src_len);
		g_assert(size - 1 == n);
	}
	return dst;
}

/**
 * Applies ascii_enforce to the string "src" copying the
 * result into "dst" if "dst_size" is sufficiently large.
 *
 * @param dst the destination buffer.
 * @param dst_size the size in bytes of the destination buffer.
 * @param src a NUL-terminated string.
 * @return If dst_size was sufficient dst is returned, otherwise
 *		   a newly allocated buffer.
 *
 */
static char *
hyper_ascii_enforce(char *dst, size_t dst_size, const char *src)
{
	size_t n;

	g_assert(src);
	g_assert(0 == dst_size || dst);

	n = ascii_enforce(dst, dst_size, src);
	if (n >= dst_size) {
		size_t size = 1 + n;

		dst = g_malloc(size);
		n = ascii_enforce(dst, size, src);
		g_assert(size - 1 == n);
	}
	return dst;
}


/**
 * Non-convertible characters will be replaced by '_'. The returned string
 * WILL be NUL-terminated in any case.
 *
 * In case of an unrecoverable error, NULL is returned.
 *
 * @param src	a NUL-terminated string.
 *
 * @return		a pointer to a newly allocated buffer holding the converted
 *				string.
 */
static char *
utf8_to_filename_charset(const char *src)
{
	char sbuf[1024], *dst;

	g_assert(src);

	dst = hyper_iconv(cd_utf8_to_filename,
			sbuf, sizeof sbuf, src, (size_t) -1, FALSE);

	if (!dst)
		dst = primary_filename_charset_is_utf8()
			? hyper_utf8_enforce(sbuf, sizeof sbuf, src, (size_t) -1)
			: hyper_ascii_enforce(sbuf, sizeof sbuf, src);

	return sbuf != dst ? dst : g_strdup(sbuf);
}

/**
 * Converts the UTF-8 encoded src string to a string encoded in the
 * primary filename character set.
 *
 * @param src a NUL-terminated UTF-8 encoded string.
 * @return a pointer to a newly allocated buffer holding the converted string.
 */
char *
utf8_to_filename(const char *src)
{
	char *filename;

	g_assert(src);

	filename = utf8_to_filename_charset(src);
	if (primary_filename_charset_is_utf8() && !is_ascii_string(filename)) {
		char *p = filename;
		filename = utf8_normalize(p, UNI_NORM_FILESYSTEM);
		G_FREE_NULL(p);
	}

	return filename;
}

/**
 * Non-convertible characters will be replaced by '_'. The returned string
 * WILL be NUL-terminated in any case.
 *
 * In case of an unrecoverable error, NULL is returned.
 *
 * @param src a NUL-terminated string.
 * @return a pointer to a newly allocated buffer holding the converted string.
 */
char *
utf8_to_locale(const char *src)
{
	char *dst;

	g_assert(src);

	dst = hyper_iconv(cd_utf8_to_locale, NULL, 0, src, (size_t) -1, FALSE);
	if (!dst)
		dst = locale_is_utf8()
			? hyper_utf8_enforce(NULL, 0, src, (size_t) -1)
			: hyper_ascii_enforce(NULL, 0, src);
	return dst;
}

/**
 * Convert arbitrary buffer to UTF-8 using the proper converter.
 *
 * @param cd		the converter
 * @param src		the string, NUL-terminated unless src_len != -1
 * @param src_len	length of src; of -1, will be computed using srtlen(src)
 *
 * @return newly allocated string in UTF-8.
 */
static char *
convert_to_utf8_len(iconv_t cd, const char *src, size_t src_len)
{
	char sbuf[4096];
	char *dst;

	g_assert(src);

	dst = hyper_iconv(cd, sbuf, sizeof sbuf, src, src_len, FALSE);
	if (!dst)
		dst = hyper_utf8_enforce(sbuf, sizeof sbuf, src, src_len);

	return sbuf != dst ? dst : g_strdup(sbuf);
}

/**
 * Convert NUL-terminated string to UTF-8 using the proper converter.
 *
 * @param cd		the converter
 * @param src		the string, NUL-terminated
 *
 * @return newly allocated string in UTF-8.
 */
static char *
convert_to_utf8(iconv_t cd, const char *src)
{
	return convert_to_utf8_len(cd, src, (size_t) -1);
}

/**
 * Converts a string from the locale's character set to UTF-8 encoding.
 * The returned string is in no defined Unicode normalization form.
 *
 * @param src a NUL-terminated string.
 * @return a newly allocated UTF-8 encoded string.
 */
char *
locale_to_utf8(const char *src)
{
	g_assert(src);

	return convert_to_utf8(cd_locale_to_utf8, src);
}

/**
 * Converts a string from ISO-8859-1 to UTF-8 encoding.
 * The returned string is in no defined Unicode normalization form.
 *
 * @param src a NUL-terminated string.
 * @return a newly allocated UTF-8 encoded string.
 */
char *
iso8859_1_to_utf8(const char *src)
{
	g_assert(src);

	return convert_to_utf8(utf8_cd_get(UTF8_CD_ISO8859_1), src);
}

/**
 * Converts a string from UTF-8 to ISO-8859-1 encoding.
 *
 * @param src a NUL-terminated string.
 * @return a newly allocated ISO-8859-1 encoded string.
 */
char *
utf8_to_iso8859_1(const char *src)
{
	char *dst;

	g_assert(src);

	dst = hyper_iconv(cd_utf8_to_iso8859_1, NULL, 0, src, (size_t) -1, FALSE);
	return dst ? dst : hyper_ascii_enforce(NULL, 0, src);
}

/**
 * Converts an arbitrary buffer from a given charset to UTF-8.
 *
 * @param cs		the charset name
 * @param src		source buffer
 * @param src_len	length of source buffer
 *
 * @return a newly allocated UTF-8 encoded string, NULL on error.
 */
char *
charset_to_utf8(const char *cs, const char *src, size_t src_len)
{
	const char *alias;
	char *result = NULL;

	alias = get_iconv_charset_alias(cs);

	if (alias != NULL) {
		iconv_t cd;

		cd = conv_to_utf8_cd_get(alias);
		if (cd != (iconv_t) -1)
			result = convert_to_utf8_len(cd, src, src_len);
	}

	return result;
}

#if CHAR_BIT == 8
#define IS_NON_NUL_ASCII(p) (*(const int8 *) (p) > 0)
#else
#define IS_NON_NUL_ASCII(p) (!(*(p) & ~0x7f) && (*(p) > 0))
#endif

bool
is_ascii_string(const char *s)
{
	while (IS_NON_NUL_ASCII(s))
		++s;

	return '\0' == *s;
}

static inline const char *
ascii_rewind(const char * const s0, const char *p)
{
	while (s0 != p && (uchar) *p < 0x80)
		p--;
	return p;
}

static inline bool
koi8_is_cyrillic_char(uchar c)
{
	return c >= 0xC0;
}

static bool
looks_like_koi8(const char *src)
{
	const char *s = src;
	size_t n = 0;
	uchar c;

	for (s = src; (c = *s) >= 0x20; s++)
		n += koi8_is_cyrillic_char(c);

	return '\0' == c && n > 0 && (s - src) > 10 && (s - src) / n < 2;

}

/* Checks for the common codepoint range of ISO8859-x encodings */
static inline bool
iso8859_is_valid_char(uchar c)
{
	/* 0x20..0x7E and 0xA0..0xFF are valid */
	return 0 != (0x60 & c) && (0x7f != c);

}

static inline bool
iso8859_6_is_arabic_char(uchar c)
{
	return c >= 0xC1; /* Ignore 0xF3..0xFF here */
}

static inline bool
iso8859_6_is_valid_char(uchar c)
{
	return iso8859_is_valid_char(c) && (
				c < 0x80 ||
				(c >= 0xC1 && c <= 0xDA) ||
				(c >= 0xE0 && c <= 0xF2) ||
				0xA0 == c ||
				0xA4 == c ||
				0xAC == c ||
				0xAD == c ||
				0xBB == c ||
				0xBF == c
			);
}

static bool
looks_like_iso8859_6(const char *src)
{
	const char *s;
	size_t n = 0;
	uchar c;

	for (s = src; iso8859_6_is_valid_char(c = *s); s++)
		n += iso8859_6_is_arabic_char(c);

	/* Rewind over trailing ASCII for better ratio detection */
	s = ascii_rewind(src, s);

	return '\0' == c && n > 0 && (s - src) > 8 && (s - src) / n < 2;
}


static inline bool
iso8859_7_is_greek_char(uchar c)
{
	return c >= 0xB0; /* Ignore 0xFF here */
}

static bool
looks_like_iso8859_7(const char *src)
{
	const char *s;
	size_t n = 0;
	uchar c;

	for (s = src; iso8859_is_valid_char(c = *s) && 0xD2 != c; s++)
		n += iso8859_7_is_greek_char(c);

	/* Rewind over trailing ASCII for better ratio detection */
	s = ascii_rewind(src, s);

	return '\0' == c && n > 0 && (s - src) > 8 && (s - src) / n < 2;
}

static inline bool
iso8859_8_is_hebrew_char(uchar c)
{
	return c >= 0xE0; /* Ignore 0xFB..0xFF here */
}

static inline bool
iso8859_8_is_valid_char(uchar c)
{
	return iso8859_is_valid_char(c) && (
			 	c < 0x80 ||
			 	(c >= 0xA2 && c <= 0xBE) ||
			 	(c >= 0xDF && c <= 0xFA) ||
			 	0xA0 == c ||
			 	0xFD == c ||
			 	0xFE == c
			);
}

static bool
looks_like_iso8859_8(const char *src)
{
	const char *s;
	size_t n = 0;
	uchar c;

	for (s = src; iso8859_8_is_valid_char(c = *s); s++)
		n += iso8859_8_is_hebrew_char(c);

	/* Rewind over trailing ASCII for better ratio detection */
	s = ascii_rewind(src, s);

	return '\0' == c && n > 0 && (s - src) > 8 && (s - src) / n < 2;
}

/**
 * Matches SJIS encoded strings.
 *
 * @param src	no dicument.
 *
 * SJIS encoding has code tables below:
 *
 * - ASCII/JIS Roman        "[\x00-\x7F]"
 * - JIS X 0208:1997        "[\x81-\x9F\xE0-\xFC][\x40-\x7E\x80-\xFC]"
 * - Half width Katakana    "[\xA0-\xDF]"
 */
static bool
looks_like_sjis(const char *src)
{
	const char *s;
	size_t n = 0;
	uchar c;

	for (s = src; '\0' != (c = *s); s++)
		n += (c >= 0xA0 && c <= 0xDF) ||
			(c >= 0x81 && c <= 0x9F) ||
			(c >= 0xE0 && c <= 0xFC);

	/* Rewind over trailing ASCII for better ratio detection */
	s = ascii_rewind(src, s);

	return '\0' == c && n > 0 && (s - src) / n < 2;
}

static bool
iso8859_is_valid_string(const char *src)
{
	while (iso8859_is_valid_char(*src))
		src++;

	return '\0' == *src;
}

/**
 * Converts the string to UTF-8 assuming an appropriate character set.
 *
 * The conversion result might still be rubbish but is guaranteed to be
 * UTF-8 encoded.
 *
 * The returned string is in no defined Unicode normalization form.
 *
 * @param src a NUL-terminated string.
 * @param charset_ptr	If not NULL, it will point to the name of the charset
 *						used to convert string.
 * @return the original pointer or a newly allocated UTF-8 encoded string.
 */
char *
unknown_to_utf8(const char *src, const char **charset_ptr)
{
	enum utf8_cd id = UTF8_CD_INVALID;
	iconv_t cd = (iconv_t) -1;
	char *dst;

	g_assert(src);

	if (utf8_is_valid_string(src)) {
		if (charset_ptr)
			*charset_ptr = "UTF-8";
		return deconstify_char(src);
	}

	if (looks_like_sjis(src))
		id = UTF8_CD_SJIS;

	if (iso8859_is_valid_string(src)) {
		const char *s;

		/* Skip leading ASCII for better ratio detection */
		for (s = src; IS_NON_NUL_ASCII(s); s++)
			continue;

		/* ISO8859-8 has the smallest range of special codepoints and many
		 * invalid codepoints are valid in ISO8859-6 or ISO8859-7.
		 */
		if (looks_like_iso8859_8(s))
			id = UTF8_CD_ISO8859_8;
		else if (looks_like_iso8859_6(s))
			id = UTF8_CD_ISO8859_6;
		else if (looks_like_iso8859_7(s))
			id = UTF8_CD_ISO8859_7;
		else
		 	id = UTF8_CD_ISO8859_1;
	}

	if (UTF8_CD_INVALID == id && looks_like_koi8(src))
		id = UTF8_CD_KOI8_R;

	if (UTF8_CD_INVALID != id)
		cd = utf8_cd_get(id);

	if (UTF8_CD_INVALID == id || (iconv_t) -1 == cd)
		cd = cd_locale_to_utf8;

	dst = convert_to_utf8(cd, src);
	g_assert(utf8_is_valid_string(dst));

	if (charset_ptr)
		*charset_ptr = UTF8_CD_INVALID == id ? "locale" : utf8_cd_to_name(id);

	return dst;
}

/**
 * Converts the string to UTF-8 assuming an appropriate character set.
 *
 * The conversion result might still be rubbish but is guaranteed to be
 * UTF-8 encoded.
 *
 * The returned string is in no defined Unicode normalization form.
 *
 * @param src a NUL-terminated string.
 * @return the original pointer or a newly allocated UTF-8 encoded string.
 */
char *
unknown_to_ui_string(const char *src)
{
	char *utf8_str, *ui_str;

	utf8_str = unknown_to_utf8(src, NULL);
	ui_str = utf8_to_ui_string(utf8_str);
	if (utf8_str != ui_str && utf8_str != src) {
		G_FREE_NULL(utf8_str);
	}
	return ui_str;
}

static char *
convert_to_utf8_normalized(iconv_t cd, const char *src, uni_norm_t norm)
{
	char sbuf[4096];
	char *dst;

	g_assert(src);

	dst = hyper_iconv(cd, sbuf, sizeof sbuf, src, (size_t) -1, FALSE);
	if (!dst)
		dst = hyper_utf8_enforce(sbuf, sizeof sbuf, src, (size_t) -1);

	g_assert(dst);
	g_assert(dst != src);

	{
		char *s = utf8_normalize(dst, norm);
		g_assert(s != dst);
		if (dst != sbuf) {
			G_FREE_NULL(dst);
		}
		dst = s;
	}

	return dst;
}

/**
 * Converts a string from the locale's character set to UTF-8 encoding and
 * the specified Unicode normalization form.
 *
 * @param src	the string to convert.
 * @param norm	the Unicode normalization form to use.
 *
 * @returns		a newly allocated string.
 */
char *
locale_to_utf8_normalized(const char *src, uni_norm_t norm)
{
	g_assert(src);

	return convert_to_utf8_normalized(cd_locale_to_utf8, src, norm);
}

/**
 * Converts a string from the filename character set to UTF-8 encoding and
 * the specified Unicode normalization form.
 *
 * @param src	the string to convert.
 * @param norm	the Unicode normalization form to use.
 *
 * @returns		a newly allocated string.
 */
char *
filename_to_utf8_normalized(const char *src, uni_norm_t norm)
{
	const pslist_t *sl;
	const char *s = NULL;
	char *dbuf = NULL, *dst;

	g_assert(src);

	PSLIST_FOREACH(sl_filename_charsets, sl) {
		const struct conv_to_utf8 *t = pslist_data(sl);

		conv_to_utf8_check(t);

		if (t->is_utf8)	{
			if (utf8_is_valid_string(src)) {
				s = src;
				break;
			}
		} else if (t->is_ascii) {
			if (is_ascii_string(src)) {
				s = src;
				break;
			}
		} else if (t->is_iso8859) {
			/*
			 * iconv() may not care about characters in the range
			 * 0x00..0x1F,0x7E and 0x80..BF which causes UTF-8 strings being
			 * misdetected as ISO-8859-*. Such characters are unlikely used in
			 * filenames and an underscore is about as useful as such control
			 * characters. This is especially important for the case
			 * G_FILENAME_ENCODING=ISO-8859-* when some filenames are UTF-8
			 * encoded.
			 */
			if (!iso8859_is_valid_string(src))
				continue;
			if (is_ascii_string(src)) {
				s = src;
				break;
			}
		}

		dbuf = hyper_iconv(t->cd, NULL, 0, src, (size_t) -1, TRUE);
		if (dbuf) {
			s = dbuf;
			break;
		}
	}

	if (!s) {
		if (!utf8_is_valid_string(src)) {
			g_warning("%s(): could not properly convert to UTF-8: \"%s\"",
				G_STRFUNC, src);
		}
		g_assert(NULL == dbuf);
		dbuf = hyper_utf8_enforce(NULL, 0, src, (size_t) -1);
		s = dbuf;
	}

	dst = utf8_normalize(s, norm);
	if (dbuf != dst) {
		G_FREE_NULL(dbuf);
	}
	return dst;
}

/**
 * Converts a string from the ISO-8859-1 character set to UTF-8 encoding and
 * the specified Unicode normalization form.
 *
 * @param src	the string to convert.
 * @param norm	the Unicode normalization form to use.
 *
 * @returns		a newly allocated string.
 */
char *
iso8859_1_to_utf8_normalized(const char *src, uni_norm_t norm)
{
	g_assert(src);

	return convert_to_utf8_normalized(utf8_cd_get(UTF8_CD_ISO8859_1),
				src, norm);
}

/**
 * Converts a string from the ISO-8859-1 character set to UTF-8 encoding and
 * the specified Unicode normalization form.
 *
 * @param src	the string to convert.
 * @param norm	the Unicode normalization form to use.
 * @param charset_ptr	no document.
 *
 * @returns		Either the original src pointer or a newly allocated string.
 */
char *
unknown_to_utf8_normalized(const char *src, uni_norm_t norm,
	const char **charset_ptr)
{
	char *s_utf8, *s_norm;

	s_utf8 = unknown_to_utf8(src, charset_ptr); /* May return src */
	if (s_utf8 == src || is_ascii_string(s_utf8))
		return s_utf8;

	s_norm = utf8_normalize(s_utf8, norm);
	if (src != s_utf8) {
		G_FREE_NULL(s_utf8);
	}
	return s_norm;
}

char *
utf8_to_ui_string(const char *src)
{
	g_assert(src);
	g_assert(utf8_is_valid_string(src));

	if (ui_uses_utf8_encoding() || locale_is_utf8()) {
		return deconstify_char(src);
	} else {
		return utf8_to_locale(src);
	}
}

char *
ui_string_to_utf8(const char *src)
{
	g_assert(src);

	if (ui_uses_utf8_encoding() || locale_is_utf8()) {
		/* XXX: If the implementation is too crappy to filter invalid
		 * 		UTF-8 codepoints the assertion below might actually fail.
		 */
		g_assert(utf8_is_valid_string(src));
		return deconstify_char(src);
	} else {
		return locale_to_utf8(src);
	}
}

static char *
locale_to_ui_string(const char *src)
{
	g_assert(src);

	if (ui_uses_utf8_encoding()) {
		return locale_to_utf8_normalized(src, UNI_NORM_GUI);
	} else {
		return deconstify_char(src);
	}
}

static char *
locale_to_ui_string2(const char *src)
{
	return locale_to_ui_string(src);
}

static char *
filename_to_ui_string(const char *src)
{
	char *name_utf8;

	g_assert(src);

	name_utf8 = filename_to_utf8_normalized(src, UNI_NORM_GUI);
	if (ui_uses_utf8_encoding() || locale_is_utf8()) {
		return name_utf8;
	} else {
		char *name_locale;

		name_locale = utf8_to_locale(name_utf8);
		if (name_utf8 != src && name_utf8 != name_locale) {
			G_FREE_NULL(name_utf8);
		}
		return name_locale;
	}
}

/**
 * This macro is used to generate "lazy" variants of the converter functions.
 *
 * In this context "lazy" means that the function will either return the
 * original string (if appropriate) or a newly allocated string but the newly
 * allocated string MUST NOT be freed. Instead the memory will be released
 * when the function is used again. Thus the handling is similar to that of
 * functions which return static buffers except that the functions are not
 * limited to a fixed buffer size. The return type has a const qualifier so
 * that a blatant attempt to free the memory is usually caught at compile
 * time. If the result is not the original string, it MUST NOT be passed as
 * parameter to this function. The last allocated buffer will normally be
 * leaked at exit time. However, if you pass an empty string, the last
 * allocated buffer is released and the empty string itself is returned. This
 * is not strictly necessary but it may be used to get rid of useless
 * warnings about a "memory leak" or to keep the memory foot-print lower.
 */
#define LAZY_CONVERT(func, proto,params) \
const char * \
CAT2(lazy_,func) proto \
{ \
	static char *prev; /* Previous conversion result */ \
	char *dst; \
 \
	g_assert(src); \
	g_assert(prev != src); \
 \
	G_FREE_NULL(prev); \
 \
	dst = func params; \
	if (dst != src) \
		prev = NOT_LEAKING(dst); \
	return dst; \
}

/**
 * FIXME: temporary until everything is converted to use halloc().
 * Same a LAZY_CONVERT() but for halloc()-ed strings.
 */
#define LAZY_CONVERT_HALLOC(func, proto,params) \
const char * \
CAT2(lazy_,func) proto \
{ \
	static char *prev; /* Previous conversion result */ \
	char *dst; \
 \
	g_assert(src); \
	g_assert(prev != src); \
 \
	HFREE_NULL(prev); \
 \
	dst = func params; \
	if (dst != src) \
		prev = dst; \
	return NOT_LEAKING(dst); \
}

/*
 * Converts the supplied string ``src'' from the current locale encoding
 * to an UTF-8 NFC string.
 *
 * @param src	the string to convert.
 * @param norm	no document.
 *
 * @returns		the converted string or ``src'' if no conversion was
 *				necessary.
 */
LAZY_CONVERT(locale_to_utf8_normalized,
		(const char *src, uni_norm_t norm), (src, norm))
LAZY_CONVERT(locale_to_utf8, (const char *src), (src))
LAZY_CONVERT(utf8_to_locale, (const char *src), (src))

LAZY_CONVERT(iso8859_1_to_utf8, (const char *src), (src))
LAZY_CONVERT(utf8_to_iso8859_1, (const char *src), (src))
LAZY_CONVERT(unknown_to_ui_string, (const char *src), (src))

LAZY_CONVERT(filename_to_ui_string, (const char *src), (src))
LAZY_CONVERT(filename_to_utf8_normalized,
		(const char *src, uni_norm_t norm), (src, norm))

/*
 * Converts the supplied string ``src'' from a guessed encoding
 * to an UTF-8 string using the given normalization form.
 *
 * @param src			the string to convert.
 * @param norm			no document.
 * @param charset_ptr	no document.
 *
 * @returns		the converted string or ``src'' if no conversion was
 *				necessary.
 */
LAZY_CONVERT(unknown_to_utf8_normalized,
		(const char *src, uni_norm_t norm, const char **charset_ptr),
		(src, norm, charset_ptr))

/*
 * Converts a string as returned by the UI toolkit to UTF-8 but returns the
 * original pointer if no conversion is necessary.  Do not free the returned
 * string. The previously returned pointer may become invalid when calling this
 * function again.
 */
LAZY_CONVERT(ui_string_to_utf8, (const char *src), (src))
LAZY_CONVERT(utf8_to_ui_string, (const char *src), (src))

LAZY_CONVERT(locale_to_ui_string, (const char *src), (src))
LAZY_CONVERT(locale_to_ui_string2, (const char *src), (src))

/**
 * Converts a UTF-8 encoded string to a UTF-16 encoded string.
 *
 * The target string ``out'' will always be zero-terminated unless
 * ``size'' is zero.
 *
 * When called with a NULL destination, it computes the size of the
 * resulting converted string.
 *
 * @param in	the UTF-8 input string.
 * @param out	the target buffer for converted UTF-16 string.
 * @param size	the length of the outbuf buffer - characters not
 *				bytes! Whether the buffer was too small can be
 *				checked by comparing ``size'' with the return value.
 *				The value of ``size'' MUST NOT exceed INT_MAX.
 *
 * @returns		the length in characters of completely converted
 *				string.
 */
size_t
utf8_to_utf16(const char *in, uint16 *out, size_t size)
{
	const char *s = in;
	uint16 *p = out;

	g_assert(in != NULL);
	g_assert(size == 0 || out != NULL);
	g_assert(size <= INT_MAX);

	if (size > 0) {

		size--;	/* Reserve one for NUL-termination */
		while (size > 0) {
			uint32 uc;
			uint16 buf[2];
			unsigned int in_len, out_len;

			uc = utf8_decode_char_fast(s, &in_len);
			if (0x0000 == uc)
				break;

			out_len = utf16_encode_char(uc, buf);
			if (0 == out_len || out_len > size)
				break;

			size -= out_len;
			s += in_len;
			*p++ = buf[0];
			if (out_len > 1) {
				*p++ = buf[1];
			}
		}
		*p = 0x0000;
	}

	if (*s != '\0') {
		uint32 uc;
		unsigned in_len;

		while (0x0000 != (uc = utf8_decode_char_fast(s, &in_len))) {
			s += in_len;
			p += utf16_encoded_char_len(uc);
		}
	}

	return p - out;
}

/**
 * Duplicate a UTF-8 encoded string an a UTF-16 encoded string.
 *
 * @return newly halloc()ed string.
 */
uint16 *
utf8_to_utf16_string(const char *in)
{
	size_t n;
	uint16 *out;

	n = 1 + utf8_to_utf16(in, NULL, 0);
	HALLOC_ARRAY(out, n);
	utf8_to_utf16(in, out, n);
	return out;
}

/**
 * @note If decoding was successful and the resulting codepoint is
 *		 greater than 0xFFFF, "next" has been used and should be skipped
 * 		 when decoding successively.
 * @return (uint32) -1 on failure,
 */
static inline uint32
utf16_decode_pair(uint16 c, uint16 next)
{
	uint32 w1, w2;

	if (c < UNI_SURROGATE_FIRST)
		return c;
	if (UNI_ILLEGAL == c)
		return (uint32) -1;
	if (c > UNI_SURROGATE_LAST)
		return c;
	if (next < UNI_SURROGATE_SECOND || next > UNI_SURROGATE_LAST)
		return (uint32) -1;

	w1 = c & ~UNI_SURROGATE_FIRST;
	w2 = next & ~UNI_SURROGATE_SECOND;
	return 0x10000UL | (w1 << 10) | w2;
}

static inline uint32
utf16_decode_char(const uint16 *s, uint *retlen)
{
	uint32 uc;

	uc = utf16_decode_pair(s[0], 0x0000 != s[0] ? s[1] : 0x0000);
	*retlen = utf16_encoded_char_len(uc);
	return uc;
}

/**
 * Converts a UTF-16 encoded string to a UTF-8 encoded string.
 *
 * The target string ``out'' will always be zero-terminated unless
 * ``size'' is zero.
 *
 * When called with a NULL destination, it computes the size of the
 * resulting converted string.
 *
 * @param src	the UTF-16 input string.
 * @param dst	the target buffer for converted UTF-8 string.
 * @param size	the length of the outbuf buffer in bytes.
 *				Whether the buffer was too small can be checked by
 *				comparing ``size'' with the return value. The value
 *				of ``size'' MUST NOT exceed INT_MAX.
 *
 * @returns the length in bytes of completely converted string.
 */
size_t
utf16_to_utf8(const uint16 *src, char *dst, size_t size)
{
	char *p = dst;
	uint32 uc;

	g_assert(src != NULL);
	g_assert(size == 0 || dst != NULL);
	g_assert(size <= INT_MAX);

	if (size > 0) {
		size--;
		while (0x0000 != *src && size > 0) {
			uint in_len, out_len;

			uc = utf16_decode_char(src, &in_len);
			if (0x0000 == uc || 0 == in_len)
				break;

			out_len = utf8_encode_char(uc, p, size);
			if (0 == out_len || out_len > size)
				break;

			src += in_len;
			p += out_len;
			size -= out_len;
		}
		*p = '\0';
	}

	while (0x0000 != *src) {
		uint in_len, out_len;

		uc = utf16_decode_char(src, &in_len);
		if (0 == in_len)
			break;

		out_len = utf8_encoded_char_len(uc);
		if (0 == out_len)
			break;

		p += out_len;
		src += in_len;
	}

	return p - dst;
}

/**
 * Converts an UTF-16 encoded string to UTF-8.
 *
 * @return newly halloc()ed string.
 */
char *
utf16_to_utf8_string(const uint16 *in)
{
	size_t n;
	char *out;

	n = 1 + utf16_to_utf8(in, NULL, 0);
	HALLOC_ARRAY(out, n);
	utf16_to_utf8(in, out, n);
	return out;
}

/**
 * Converts a UTF-8 encoded string to a UTF-32 encoded string.
 *
 * The target string ``out'' is always be zero-terminated unless
 * ``size'' is zero.
 *
 * @param in	the UTF-8 input string.
 * @param out	the target buffer for converted UTF-32 string.
 * @param size	the length of the outbuf buffer - characters not
 *				bytes! Whether the buffer was too small can be
 *				checked by comparing ``size'' with the return value.
 *				The value of ``size'' MUST NOT exceed INT_MAX.
 *
 * @returns		the length in characters of completely converted
 *				string.
 */
static size_t
utf8_to_utf32(const char *in, uint32 *out, size_t size)
{
	const char *s = in;
	uint32 *p = out;
	uint retlen;

	g_assert(in != NULL);
	g_assert(size == 0 || out != NULL);
	g_assert(size <= INT_MAX);

	if (size > 0) {
		uint32 uc;

		while (--size > 0) {
			uc = utf8_decode_char_fast(s, &retlen);
			if (!uc)
				break;
			*p++ = uc;
			s += retlen;
		}
		*p = 0x0000;
	}

	if (*s != '\0') {
		while (utf8_decode_char_fast(s, &retlen)) {
			s += retlen;
			p++;
		}
	}

	return p - out;
}

/**
 * Converts a UTF-32 encoded string to a UTF-8 encoded string.
 *
 * The target string ``out'' is always be zero-terminated unless
 * ``size'' is zero.
 *
 * @param src	the UTF-32 input string.
 * @param dst	the target buffer for converted UTF-8 string.
 * @param size	the length of the outbuf buffer in bytes.
 *				Whether the buffer was too small can be checked by
 *				comparing ``size'' with the return value. The value
 *				of ``size'' MUST NOT exceed INT_MAX.
 *
 * @returns the length in bytes of completely converted string.
 */
size_t
utf32_to_utf8(const uint32 *src, char *dst, size_t size)
{
	char *p = dst;
	uint32 uc;

	g_assert(src != NULL);
	g_assert(size == 0 || dst != NULL);
	g_assert(size <= INT_MAX);

	if (size > 0) {

		size--;
		while (0x0000 != (uc = *src) && size > 0) {
			unsigned out_len = utf8_encode_char(uc, p, size);

			if (0 == out_len || out_len > size)
				break;

			src++;
			p += out_len;
			size -= out_len;
		}
		*p = '\0';
	}

	while (0x0000 != (uc = *src++)) {
		unsigned out_len = utf8_encoded_char_len(uc);

		if (0 == out_len)
			break;
		p += out_len;
	}

	return p - dst;
}

/**
 * Converts a UTF-32 encoded string to a UTF-8 encoded string.
 *
 * The target string ``out'' is always be zero-terminated unless
 * ``size'' is zero.
 *
 * @param buf	the UTF-32 input string.
 *
 * @returns		the length in bytes of completely converted string.
 */
static size_t
utf32_to_utf8_inplace(uint32 *buf)
{
	const uint32 *src = buf;
	char *dst = cast_to_char_ptr(buf);
	uint32 uc;
	uint len;

	g_assert(buf != NULL);

	for (src = buf; 0x0000 != (uc = *src++); dst += len) {
		len = utf8_encode_char(uc, dst, sizeof *buf);
		if (0 == len)
			break;
	}
	*dst = '\0';

	return dst - cast_to_char_ptr(buf);
}

/**
 * The equivalent of g_strdup() for UTF-32 strings.
 */
static uint32 *
utf32_strdup(const uint32 *s)
{
	uint32 *p;
	size_t n;

	if (!s)
		return NULL; /* Just because g_strdup() does it like this */

	n = (1 + utf32_strlen(s)) * sizeof *p;
	p = g_malloc(n);
	memcpy(p, s, n);
	return p;
}

static gint64
utf32_strcmp(const uint32 *s1, const uint32 *s2)
{
	uint32 uc;

	g_assert(NULL != s1);
	g_assert(NULL != s2);

	while (0x0000 != (uc = *s1++) && *s2 == uc)
		s2++;

	return uc - *s2;
}

/**
 * Looks up the decomposed string for an UTF-32 character.
 *
 * @param uc	the unicode character to look up.
 * @param nfkd	if TRUE, compatibility composition is used, otherwise
 *				canonical composition.
 *
 * @returns NULL if the character is not in decomposition table. Otherwise,
 *          the returned pointer points to a possibly unterminated UTF-32
 *			string of maximum UTF32_NFD_REPLACE_MAXLEN characters. The result
 *			is constant.
 */
static const uint32 *
utf32_decompose_lookup(uint32 uc, bool nfkd)
{
	/* utf32_nfkd_lut contains UTF-32 strings, so we return a pointer
	 * to the respective entry instead of copying the string */

#define GET_ITEM(i) (utf32_nfkd_lut[(i)].c & ~UTF32_F_MASK)
#define FOUND(i) G_STMT_START { \
	return utf32_nfkd_lut[(i)].c & (nfkd ? 0 : UTF32_F_NFKD) \
		? NULL \
		: utf32_nfkd_lut[(i)].d; \
	/* NOTREACHED */ \
} G_STMT_END

	/* Perform a binary search to find ``uc'' */
	BINARY_SEARCH(uint32, uc, N_ITEMS(utf32_nfkd_lut), CMP,
		GET_ITEM, FOUND);

#undef FOUND
#undef GET_ITEM
	return NULL;
}

/**
 * Looks up the simple uppercase variant of an UTF-32 character.
 *
 * @return the uppercase variant of ``uc'' or ``uc'' itself.
 */

static uint32
utf32_uppercase(uint32 uc)
{
	if (UNICODE_IS_ASCII(uc))
		return is_ascii_lower(uc) ? (uint32) ascii_toupper(uc) : uc;

#define GET_ITEM(i)	(utf32_uppercase_lut[(i)].lower)
#define FOUND(i)	return utf32_uppercase_lut[(i)].upper

	/* Perform a binary search to find ``uc'' */
	BINARY_SEARCH(uint32, uc, N_ITEMS(utf32_uppercase_lut), CMP,
		GET_ITEM, FOUND);

#undef FOUND
#undef GET_ITEM

	/* Deseret block */
	if (uc >= 0x10428 && uc <= 0x1044F)
		return uc - 0x28;

	return uc; /* not found */
}

/**
 * Looks up the simple lowercase variant of an UTF-32 character.
 *
 * @return the lowercase variant of ``uc'' or ``uc'' itself.
 */
uint32 G_HOT
utf32_lowercase(uint32 uc)
{
	if (UNICODE_IS_ASCII(uc))
		return is_ascii_upper(uc) ? (uint32) ascii_tolower(uc) : uc;

#define GET_ITEM(i)	(utf32_lowercase_lut[(i)].upper)
#define FOUND(i)	return utf32_lowercase_lut[(i)].lower

	/* Perform a binary search to find ``uc'' */
	BINARY_SEARCH(uint32, uc, N_ITEMS(utf32_lowercase_lut), CMP,
		GET_ITEM, FOUND);

#undef FOUND
#undef GET_ITEM

	/* Deseret block */
	if (uc >= 0x10400 && uc <= 0x10427)
		return uc + 0x28;

	return uc; /* not found */
}

/**
 * Looks up the simple lowercase variant of an UTF-32 character.
 *
 * @return the lowercase variant of ``uc'' or ``uc'' itself.
 */
static const uint32 *
utf32_special_folding(uint32 uc)
{
#define GET_ITEM(i)	(utf32_special_folding_lut[(i)].uc)
#define FOUND(i)	return utf32_special_folding_lut[(i)].folded

	/* Perform a binary search to find ``uc'' */
	BINARY_SEARCH(uint32, uc, N_ITEMS(utf32_special_folding_lut), CMP,
		GET_ITEM, FOUND);

#undef FOUND
#undef GET_ITEM

	return NULL;
}

/**
 * Finds the composition of two UTF-32 characters.
 *
 * @param a an UTF-32 character (should be a starter)
 * @param b an UTF-32 character
 *
 * @return	zero if there's no composition for the characters. Otherwise,
 *			the composed character is returned.
 */
static uint32
utf32_compose_char(uint32 a, uint32 b)
{
	pslist_t *sl;
	void *key;

	key = GUINT_TO_POINTER(a);
	sl = htable_lookup(utf32_compose_roots, key);
	for (/* NOTHING */; sl; sl = pslist_next(sl)) {
		uint i;
		uint32 c;

		i = GPOINTER_TO_UINT(sl->data);
		c = utf32_nfkd_lut[i].d[1];
		if (b == c) {
			return utf32_nfkd_lut[i].c & ~UTF32_F_MASK;
		} else if (b < c) {
			/* The lists are sorted */
			break;
		}
	}

	return 0;
}

/**
 * Finds the next ``starter'' character (combining class zero) in the
 * string starting at ``s''. Note that NUL is also a ``starter''.
 *
 * @param s a NUL-terminated UTF-32 string.
 * @return a pointer to the next ``starter'' character in ``s''.
 */
static inline uint32 *
utf32_next_starter(const uint32 *s)
{
	while (0 != utf32_combining_class(*s))
		s++;
	return deconstify_uint32(s);
}


/**
 * Checks whether an UTF-32 string is in canonical order.
 */
bool
utf32_canonical_sorted(const uint32 *src)
{
	uint32 uc;
	uint prev, cc;

	for (prev = 0; 0 != (uc = *src++); prev = cc) {
		cc = utf32_combining_class(uc);
		if (cc != 0 && prev > cc)
			return FALSE;
	}

	return TRUE;
}

static inline bool
utf32_is_decomposed_char(uint32 uc, bool nfkd)
{
	if (UNICODE_IS_ASCII(uc)) {
		return TRUE;
	} else if (UNICODE_IS_HANGUL(uc)) {
		return FALSE;
	} else {
		return NULL == utf32_decompose_lookup(uc, nfkd);
	}
}

/**
 * Checks whether an UTF-32 string is decomposed.
 */
bool
utf32_is_decomposed(const uint32 *src, bool nfkd)
{
	uint32 uc;
	uint prev, cc;

	for (prev = 0; 0 != (uc = *src++); prev = cc) {
		cc = utf32_combining_class(uc);
		if (cc != 0 && prev > cc)
			return FALSE;
		if (!utf32_is_decomposed_char(uc, nfkd))
			return FALSE;
	}

	return TRUE;
}

/**
 * Puts an UTF-32 string into canonical order.
 */
static uint32 *
utf32_sort_canonical(uint32 *src)
{
	uint32 *s = src, *stable = src, uc;
	uint prev, cc;

	for (prev = 0; 0 != (uc = *s); prev = cc) {
		cc = utf32_combining_class(uc);
		if (cc == 0) {
			stable = s++;
		} else if (prev <= cc) {
			s++;
		} else {
			uint32 *p;

			while (0 != utf32_combining_class(*++s))
				;

			/* Use insertion sort because we need a stable sort algorithm */
			for (p = &stable[1]; p != s; p++) {
				uint32 *q;

				uc = *p;
				cc = utf32_combining_class(uc);

				for (q = p; q != stable; q--) {
					uint32 uc2;

					uc2 = *(q - 1);
					if (cc >= utf32_combining_class(uc2))
						break;

					g_assert(q != s);
					*q = uc2;
				}

				g_assert(q != s);
				*q = uc;
			}

			stable = s;
			cc = 0;
		}
	}

	return src;
}

/**
 * Checks whether an UTF-8 encoded string is decomposed.
 */
bool
utf8_is_decomposed(const char *src, bool nfkd)
{
	uint prev, cc;
	char c;

	for (prev = 0; '\0' != (c = *src); prev = cc) {
		if (UTF8_IS_ASCII(c)) {
			src++;
			cc = 0;
		} else {
			uint32 uc;
			uint retlen;

			uc = utf8_decode_char_fast(src, &retlen);
			if (uc == 0x0000)
				break;

			cc = utf32_combining_class(uc);
			if (cc != 0 && prev > cc)
				return FALSE;

			if (!utf32_is_decomposed_char(uc, nfkd))
				return FALSE;

			src += retlen;
		}
	}

	return TRUE;
}

/**
 * Checks whether an UTF-8 encoded string is in canonical order.
 */
static bool
utf8_canonical_sorted(const char *src)
{
	uint prev, cc;
	char c;

	for (prev = 0; '\0' != (c = *src); prev = cc) {
		if (UTF8_IS_ASCII(c)) {
			src++;
			cc = 0;
		} else {
			uint32 uc;
			uint retlen;

			uc = utf8_decode_char_fast(src, &retlen);
			if (uc == 0x0000)
				break;

			cc = utf32_combining_class(uc);
			if (cc != 0 && prev > cc)
				return FALSE;

			src += retlen;
		}
	}

	return TRUE;
}

/**
 * Puts an UTF-8 encoded string into canonical order.
 */
static char *
utf8_sort_canonical(char *src)
{
	uint32 *buf32, *d, a[1024];
	size_t size8, size32, n;

	/* XXX: Sorting combine characters is rather heavy with UTF-8 encoding
	 *		because the characters have variable byte lengths. Therefore
	 *		and for simplicity, the whole string is temporarily converted
	 *		to UTF-32 and then put into canonical order. An optimization
	 *		could be converting only between stable code points. However,
	 *		in the worst case, that's still the whole string.
	 */

	size8 = 1 + strlen(src);
	size32 = 1 + utf8_to_utf32(src, NULL, 0);

	/* Use an auto buffer for reasonably small strings */
	if (size32 > N_ITEMS(a)) {
		d = g_malloc(size32 * sizeof *buf32);
		buf32 = d;
	} else {
		d = NULL;
		buf32 = a;
	}

	n = utf8_to_utf32(src, buf32, size32);
	g_assert(n == size32 - 1);
	utf32_sort_canonical(buf32);
	n = utf32_to_utf8(buf32, src, size8);
	g_assert(n == size8 - 1);

	G_FREE_NULL(d);

	return src;
}

/**
 * Decomposes a Hangul character.
 *
 * @param uc must be a Hangul character
 * @param buf must be at least three elements large
 * @return the length of the decomposed character.
 */
static inline uint
utf32_decompose_hangul_char(uint32 uc, uint32 *buf)
{
	/*
	 * Take advantage of algorithmic Hangul decomposition to reduce
	 * the size of the lookup table drastically. See also:
	 *
	 * 		http://www.unicode.org/reports/tr15/#Hangul
	 */
#define T_COUNT 28
#define V_COUNT 21
#define N_COUNT (T_COUNT * V_COUNT)
	static const uint32 l_base = 0x1100;
	static const uint32 v_base = 0x1161;
	static const uint32 t_base = 0x11A7;
	const uint32 i = uc - UNI_HANGUL_FIRST;
	uint32 t_mod = i % T_COUNT;

	buf[0] = l_base + i / N_COUNT;
	buf[1] = v_base + (i % N_COUNT) / T_COUNT;
#undef N_COUNT
#undef V_COUNT
#undef T_COUNT

	if (!t_mod)
		return 2;

	buf[2] = t_base + t_mod;
	return 3;
}

/**
 * Composes all Hangul characters in a string.
 */
static inline size_t
utf32_compose_hangul(uint32 *src)
{
#define L_COUNT 19
#define T_COUNT 28
#define V_COUNT 21
#define N_COUNT (T_COUNT * V_COUNT)
#define S_COUNT (L_COUNT * N_COUNT)
	static const uint32 l_base = 0x1100;
	static const uint32 v_base = 0x1161;
	static const uint32 t_base = 0x11A7;
	static const uint32 s_base = 0xAC00;
	uint32 uc, prev, *p, *s = src;

	if (0 == (prev = *s))
		return 0;

	for (p = ++s; 0 != (uc = *s); s++) {
		int l_index, s_index;

		l_index	= prev - l_base;
		if (0 <= l_index && l_index < L_COUNT) {
			int v_index = uc - v_base;

			if (0 <= v_index && v_index < V_COUNT) {
				prev = s_base + (l_index * V_COUNT + v_index) * T_COUNT;
				*(p - 1) = prev;
				continue;
			}
		}

		s_index = prev - s_base;
		if (0 <= s_index && s_index < S_COUNT && 0 == (s_index % T_COUNT)) {
			int t_index = uc - t_base;

			if (0 < t_index && t_index < T_COUNT) {
				prev += t_index;
				*(p - 1) = prev;
				continue;
			}
		}

		prev = uc;
		*p++ = uc;
	}

#undef N_COUNT
#undef V_COUNT
#undef T_COUNT
#undef L_COUNT

	*p = 0x0000;
	return p - src;
}

/**
 * Decomposes a single UTF-32 character. This must be used iteratively
 * to gain the complete decomposition.
 *
 * @param uc the UTF-32 to decompose.
 * @param len the variable ``len'' points to will be set to
 *        length in characters (not bytes!) of decomposed string. This is
 *        important because the decomposed string is not zero-terminated.
 * @param nfkd if TRUE, compatibility composition is used, otherwise
 *			canonical composition.
 *
 * @returns a pointer to a buffer holding the decomposed string.
 *			The buffer is unterminated. The maximum length is
 *			UTF32_NFKD_REPLACE_MAXLEN characters. The returned pointer points
 *			to a static buffer which might get overwritten by subsequent
 *			calls to this function.
 */
static inline const uint32 *
utf32_decompose_single_char(uint32 uc, size_t *len, bool nfkd)
{
	static uint32 buf[3];
	uint32 *p = buf;
	const uint32 *q;

	if (UNICODE_IS_ASCII(uc)) {
		*p++ = uc;
	} else if (UNICODE_IS_HANGUL(uc)) {
		p += utf32_decompose_hangul_char(uc, p);
	} else if (NULL != (q = utf32_decompose_lookup(uc, nfkd))) {
		*len = utf32_strmaxlen(q, UTF32_NFKD_REPLACE_MAXLEN);
		return q;
	} else {
		*p++ = uc;
	}

	g_assert(p > buf && p <= &buf[N_ITEMS(buf)]);
	*len = p - buf;
	return buf;
}

/**
 * Decomposes an UTF-32 character completely.
 *
 * @param uc the UTF-32 to decompose.
 * @param len the variable ``len'' points to will be set to
 *        length in characters (not bytes!) of decomposed string. This is
 *        important because the decomposed string is not zero-terminated.
 * @param nfkd if TRUE, compatibility composition is used, otherwise
 *			canonical composition.
 *
 * @returns a pointer to a buffer holding the decomposed string.
 *			The buffer is unterminated. The maximum length is
 *			UTF32_NFKD_REPLACE_MAXLEN characters. The returned pointer points
 *			to a static buffer which might get overwritten by subsequent
 *			calls to this function.
 */
static inline const uint32 *
utf32_decompose_char(uint32 uc, size_t *len, bool nfkd)
{
	static uint32 buf[2][256];
	const uint32 *old;
	uint32 *p, *cur;
	size_t size, start;

	old = utf32_decompose_single_char(uc, &size, nfkd);
	if (1 == size && uc == old[0]) {
		*len = 1;
		return old;
	}

	cur = buf[0];
	/* This must be copied because the next call to
	 * utf32_decompose_nfkd_char_single() might modify
	 * the buffer that ``old'' points to.
	 */
	memcpy(buf[1], old, size * sizeof *old);
	old = buf[1];
	start = 0;

	for (;;) {
		size_t avail, i;
		const uint32 *mod;

		mod = NULL;
		p = &cur[start];
		avail = N_ITEMS(buf[0]) - start;

		for (i = start; i < size; i++) {
			const uint32 *q;
			size_t n;

			q = utf32_decompose_single_char(old[i], &n, nfkd);
			if (!mod && (n > 1 || *q != old[i]))
				mod = &old[i];

			g_assert(n <= avail);
			avail -= n;
			while (n-- > 0)
				*p++ = *q++;
		}

		if (!mod)
			break;

		start = mod - old;
		size = p - cur;

		/* swap ``cur'' and ``old'' for next round */
		old = cur;
		cur = cur == buf[0] ? buf[1] : buf[0];
	}

	*len = size;
	return old;
}

/**
 * Determines the length of a valid NUL-terminated UTF-32 string.
 * @note Illegal codepoints are accepted and included in the count.
 *
 * @param s a NUL-terminated UTF-32 string.
 * @returns the length in characters (not bytes!) of the string ``s''.
 */
size_t
utf32_strlen(const uint32 *s)
{
	const uint32 *p = s;

	g_assert(s != NULL);

	while (*p != 0x0000)
		p++;

	return p - s;
}

/**
 * Determines the length of a UTF-32 string inspecting at most ``maxlen''
 * characters (not bytes!). This can safely be used with unterminated UTF-32
 * strings if ``maxlen'' has an appropriate value.
 *
 * To detect whether the actual string is longer than ``maxlen'' characters,
 * just check if ``string[maxlen]'' is 0x0000, if and only if the returned
 * value equals maxlen. Otherwise, the returned value is indeed the
 * complete length of the UTF-32 string.
 *
 * @param s an UTF-32 string.
 * @param maxlen the maximum number of characters to inspect.
 *
 * @returns the length in characters (not bytes!) of the string ``s''.
 */
size_t
utf32_strmaxlen(const uint32 *s, size_t maxlen)
{
	const uint32 *p = s;
	size_t i = 0;

	g_assert(s != NULL);
	g_assert(maxlen <= INT_MAX);

	while (i < maxlen && p[i])
		++i;

	return i;
}

/**
 * Decomposes an UTF-8 encoded string.
 *
 * The UTF-8 string written to ``dst'' is always NUL-terminated unless
 * ``size'' is zero. If the size of ``dst'' is too small to hold the
 * complete decomposed string, the resulting string will be truncated but
 * the validity of the UTF-8 encoding will be preserved. Truncation is
 * indicated by the return value being equal to or greater than ``size''.
 *
 * @param src a UTF-8 encoded string.
 * @param out a pointer to a buffer which will hold the decomposed string.
 * @param size the number of bytes ``dst'' can hold.
 * @param nfkd if TRUE, compatibility composition is used, otherwise
 *			canonical composition.
 *
 * @returns the length in bytes (not characters!) of completely decomposed
 *			string.
 */
static inline size_t
utf8_decompose(const char *src, char *out, size_t size, bool nfkd)
{
	const uint32 *d;
	uint32 uc;
	uint retlen;
	size_t d_len, new_len = 0;

	g_assert(src != NULL);
	g_assert(size == 0 || out != NULL);
	g_assert(size <= INT_MAX);

	if (size-- > 0) {
		char *dst = out;

		while (*src != '\0') {
			char buf[256], utf8_buf[4], *q;
			size_t utf8_len;

			uc = utf8_decode_char_fast(src, &retlen);
			if (uc == 0x0000)
				break;

			src += retlen;
			d = utf32_decompose_char(uc, &d_len, nfkd);
			q = buf;
			while (d_len-- > 0) {
				char *p = utf8_buf;

				utf8_len = utf8_encode_char(*d++, utf8_buf, sizeof utf8_buf);
				g_assert((size_t) (&buf[N_ITEMS(buf)] - q) >= utf8_len);
				while (utf8_len-- > 0)
					*q++ = *p++;
			}

			utf8_len = q - buf;
			if (size - new_len < utf8_len)
				break;

			new_len += utf8_len;
			q = buf;
			while (utf8_len-- > 0)
				*dst++ = *q++;
		}
		*dst = '\0';

		if (!utf8_canonical_sorted(out))
			utf8_sort_canonical(out);
		g_assert(utf8_canonical_sorted(out));
	}

	while (*src != '\0') {
		uc = utf8_decode_char_fast(src, &retlen);
		if (uc == 0x0000)
			break;

		src += retlen;
		d = utf32_decompose_char(uc, &d_len, nfkd);
		while (d_len-- > 0)
			new_len += uniskip(*d++);
	}

	return new_len;
}

/**
 * Decomposes (NFD) an UTF-8 encoded string.
 *
 * The UTF-8 string written to ``dst'' is always NUL-terminated unless
 * ``size'' is zero. If the size of ``dst'' is too small to hold the
 * complete decomposed string, the resulting string will be truncated but
 * the validity of the UTF-8 encoding will be preserved. Truncation is
 * indicated by the return value being equal to or greater than ``size''.
 *
 * @param src a UTF-8 encoded string.
 * @param out a pointer to a buffer which will hold the decomposed string.
 * @param size the number of bytes ``dst'' can hold.
 *
 * @returns the length in bytes (not characters!) of completely decomposed
 *			string.
 */
size_t
utf8_decompose_nfd(const char *src, char *out, size_t size)
{
	return utf8_decompose(src, out, size, FALSE);
}

/**
 * Decomposes (NFKD) an UTF-8 encoded string.
 *
 * The UTF-8 string written to ``dst'' is always NUL-terminated unless
 * ``size'' is zero. If the size of ``dst'' is too small to hold the
 * complete decomposed string, the resulting string will be truncated but
 * the validity of the UTF-8 encoding will be preserved. Truncation is
 * indicated by the return value being equal to or greater than ``size''.
 *
 * @param src a UTF-8 encoded string.
 * @param out a pointer to a buffer which will hold the decomposed string.
 * @param size the number of bytes ``dst'' can hold.
 *
 * @returns the length in bytes (not characters!) of completely decomposed
 *			string.
 */
size_t
utf8_decompose_nfkd(const char *src, char *out, size_t size)
{
	return utf8_decompose(src, out, size, TRUE);
}

/**
 * Decomposes an UTF-32 encoded string.
 *
 */
static inline size_t
utf32_decompose(const uint32 *in, uint32 *out, size_t size, bool nfkd)
{
	const uint32 *s = in;
	uint32 *p = out;
	uint32 uc;
	size_t d_len;

	g_assert(in != NULL);
	g_assert(size == 0 || out != NULL);
	g_assert(size <= INT_MAX);

	if (size-- > 0) {
		for (/* NOTHING */; 0x0000 != (uc = *s); s++) {
			const uint32 *d = utf32_decompose_char(uc, &d_len, nfkd);
			if (d_len > size)
				break;
			size -= d_len;
			while (d_len-- > 0)
				*p++ = *d++;
		}
		*p = 0x0000;

		utf32_sort_canonical(out);
	}

	while (0x0000 != (uc = *s++)) {
		(void) utf32_decompose_char(uc, &d_len, nfkd);
		p += d_len;
	}

	return p - out;
}

/**
 * Decomposes (NFD) an UTF-32 encoded string.
 *
 */
size_t
utf32_decompose_nfd(const uint32 *in, uint32 *out, size_t size)
{
	return utf32_decompose(in, out, size, FALSE);
}

/**
 * Decomposes (NFKD) an UTF-32 encoded string.
 *
 */
size_t
utf32_decompose_nfkd(const uint32 *in, uint32 *out, size_t size)
{
	return utf32_decompose(in, out, size, TRUE);
}

typedef uint32 (* utf32_remap_func)(uint32 uc);

/**
 * Copies the UTF-8 string ``src'' to ``dst'' remapping all characters
 * using ``remap''.
 * If the created string is as long as ``size'' or larger, the string in
 * ``dst'' will be truncated. ``dst'' is always NUL-terminated unless ``size''
 * is zero.
 * The returned value is the length of the converted string ``src''
 * regardless of the ``size'' parameter. ``src'' must be validly UTF-8
 * encoded, otherwise the string will be truncated.
 *
 * @param dst the target buffer
 * @param src an UTF-8 string
 * @param size the size of dst in bytes
 * @param remap a function that takes a single UTF-32 character and returns
 *        a single UTF-32 character.
 * @return the length in bytes of the converted string ``src''.
 */
static size_t
utf8_remap(char *dst, const char *src, size_t size, utf32_remap_func remap)
{
	uint32 uc;
	uint32 nuc;
	uint retlen;
	size_t new_len;

	g_assert(size == 0 || dst != NULL);
	g_assert(src != NULL);
	g_assert(remap != NULL);
	g_assert(size <= INT_MAX);

	/*
	 * This function is a hot spot.  Don't bother re-encoding
	 * the character if it's been remapped to itself: we already
	 * have the encoded form in the source!
	 *		--RAM, 2005-08-28
	 */
#define LOOP_BODY										\
	uc = utf8_decode_char_fast(src, &retlen);			\
	if (uc == 0x0000)									\
		break;											\
														\
	nuc = remap(uc);									\
	if (nuc == uc) {									\
		if (retlen > size)								\
			break;										\
														\
		size -= retlen;									\
		while (retlen-- > 0)							\
			*dst++ = *src++;							\
	} else {											\
		uint utf8_len;									\
														\
		utf8_len = utf8_encode_char(nuc, dst, size);	\
		if (utf8_len == 0 || utf8_len > size)			\
			break;										\
														\
		src += retlen;									\
		dst += utf8_len;								\
		size -= utf8_len;								\
	}

	if (size <= 0) {
		new_len = 0;
	} else {
		const char *dst0 = dst;

		size--;	/* Reserve one byte for the NUL */

		if (size > UTF8_CPU_CACHELINE) {
			/* Worth pre-fetching data */
			while (*src != '\0') {
				G_PREFETCH_R(&src[UTF8_CPU_CACHELINE]);
				G_PREFETCH_W(&dst[UTF8_CPU_CACHELINE]);

				LOOP_BODY
			}
		} else {
			/* Not worth pre-fetching data */
			while (*src != '\0') {
				LOOP_BODY
			}
		}
		new_len = dst - dst0;
		*dst = '\0';
	}

#undef LOOP_BODY

	while (*src != '\0') {
		G_PREFETCH_R(&src[UTF8_CPU_CACHELINE]);

		uc = utf8_decode_char_fast(src, &retlen);
		if (uc == 0x0000)
			break;

		src += retlen;
		nuc = remap(uc);
		new_len += nuc == uc ? retlen : uniskip(nuc);
	}

	return new_len;
}

/**
 * Copies the UTF-32 string ``src'' to ``dst'' remapping all characters
 * using ``remap''.
 * If the created string is as long as ``size'' or larger, the string in
 * ``dst'' will be truncated. ``dst'' is always NUL-terminated unless ``size''
 * is zero.
 * The returned value is the length of the converted string ``src''
 * regardless of the ``size'' parameter. ``src'' must be validly UTF-8
 * encoded, otherwise the string will be truncated.
 *
 * @param dst the target buffer
 * @param src an UTF-8 string
 * @param size the size of dst in bytes
 * @param remap a function that takes a single UTF-32 character and returns
 *        a single UTF-32 character.
 * @return the length in bytes of the converted string ``src''.
 */
static size_t
utf32_remap(uint32 *dst, const uint32 *src, size_t size,
	utf32_remap_func remap)
{
	const uint32 *s = src;
	uint32 *p = dst;

	g_assert(dst != NULL);
	g_assert(src != NULL);
	g_assert(remap != NULL);
	g_assert(size <= INT_MAX);

	if (size > 0) {
		uint32 *end, uc;

		end = &dst[size - 1];

		if (size > UTF8_CPU_CACHELINE) {
			for (p = dst; p != end && 0x0000 != (uc = *s); p++, s++) {
				G_PREFETCH_R(&s[UTF8_CPU_CACHELINE / sizeof *s]);
				G_PREFETCH_W(&p[UTF8_CPU_CACHELINE / sizeof *p]);
				*p = remap(uc);
			}
		} else {
			for (p = dst; p != end && 0x0000 != (uc = *s); p++, s++) {
				*p = remap(uc);
			}
		}
		*p = 0x0000;
	}

	if (0x0000 != *s)
		p += utf32_strlen(s);

	return p - dst;
}

/**
 * Copies ``src'' to ``dst'' converting all characters to lowercase. If
 * the string is as long as ``size'' or larger, the string in ``dst'' will
 * be truncated. ``dst'' is always NUL-terminated unless ``size'' is zero.
 * The returned value is the length of the converted string ``src''
 * regardless of the ``size'' parameter.
 *
 * @param dst the target buffer
 * @param src an UTF-32 string
 * @param size the size of dst in bytes
 * @return the length in characters of the converted string ``src''.
 */
size_t
utf32_strlower(uint32 *dst, const uint32 *src, size_t size)
{
	g_assert(dst != NULL);
	g_assert(src != NULL);
	g_assert(size <= INT_MAX);

	return utf32_remap(dst, src, size, utf32_lowercase);
}
/**
 * Copies ``src'' to ``dst'' converting all characters to uppercase. If
 * the string is as long as ``size'' or larger, the string in ``dst'' will
 * be truncated. ``dst'' is always NUL-terminated unless ``size'' is zero.
 * The returned value is the length of the converted string ``src''
 * regardless of the ``size'' parameter.
 *
 * @param dst the target buffer
 * @param src an UTF-32 string
 * @param size the size of dst in bytes
 * @return the length in characters of the converted string ``src''.
 */
size_t
utf32_strupper(uint32 *dst, const uint32 *src, size_t size)
{
	g_assert(size == 0 || dst != NULL);
	g_assert(src != NULL);
	g_assert(size <= INT_MAX);

	return utf32_remap(dst, src, size, utf32_uppercase);
}

/**
 * Copies ``src'' to ``dst'' converting all characters to lowercase. If
 * the string is as long as ``size'' or larger, the string in ``dst'' will
 * be truncated. ``dst'' is always NUL-terminated unless ``size'' is zero.
 * The returned value is the length of the converted string ``src''
 * regardless of the ``size'' parameter. ``src'' must be validly UTF-8
 * encoded, otherwise the string will be truncated.
 *
 * @param dst the target buffer
 * @param src an UTF-8 string
 * @param size the size of dst in bytes
 * @return the length in bytes of the converted string ``src''.
 */
size_t
utf8_strlower(char *dst, const char *src, size_t size)
{
	g_assert(size == 0 || dst != NULL);
	g_assert(src != NULL);
	g_assert(size <= INT_MAX);

	return utf8_remap(dst, src, size, utf32_lowercase);
}

/**
 * Copies ``src'' to ``dst'' converting all characters to uppercase. If
 * the string is as long as ``size'' or larger, the string in ``dst'' will
 * be truncated. ``dst'' is always NUL-terminated unless ``size'' is zero.
 * The returned value is the length of the converted string ``src''
 * regardless of the ``size'' parameter. ``src'' must be validly UTF-8
 * encoded, otherwise the string will be truncated.
 *
 * @param dst the target buffer
 * @param src an UTF-8 string
 * @param size the size of dst in bytes
 * @return the length in bytes of the converted string ``src''.
 */
size_t
utf8_strupper(char *dst, const char *src, size_t size)
{
	g_assert(dst != NULL);
	g_assert(src != NULL);
	g_assert(size <= INT_MAX);

	return utf8_remap(dst, src, size, utf32_uppercase);
}

/**
 * Copies the UTF-8 string ``src'' to a newly allocated buffer converting all
 * characters to lowercase.
 *
 * @param src an UTF-8 string
 * @return a newly halloc()'ed buffer containing the lowercased string.
 */
char *
utf8_strlower_copy(const char *src)
{
	char *dst;
	size_t len, size;

	g_assert(src != NULL);

	len = utf8_strlower(NULL, src, 0);
	size = len + 1;
	dst = halloc(size);
	len = utf8_strlower(dst, src, size);
	g_assert(size == len + 1);
	g_assert(len == strlen(dst));

	return dst;
}

/**
 * Copies the UTF-8 string ``src'' to a newly allocated buffer converting all
 * characters to uppercase.
 *
 * @param src an UTF-8 string
 * @return a newly allocated buffer containing the uppercased string.
 */
char *
utf8_strupper_copy(const char *src)
{
	char c, *dst;
	size_t len, size;

	g_assert(src != NULL);

	len = utf8_strupper(&c, src, sizeof c);
	g_assert(c == '\0');
	size = len + 1;
	dst = g_malloc(size);
	len = utf8_strupper(dst, src, size);
	g_assert(size == len + 1);
	g_assert(len == strlen(dst));

	return dst;
}

static size_t
utf32_case_fold_char(uint32 uc, uint32 *dst, size_t size)
{
	const uint32 *folded;
	size_t length;

	uc = utf32_lowercase(uc);
	folded = utf32_special_folding(uc);
	if (folded) {
		length = utf32_strlen(folded);
	} else {
		folded = &uc;
		length = 1;
	}
	if (size >= length) {
		memcpy(dst, folded, length * sizeof *folded);
	}
	return length;
}

static size_t
utf32_case_fold(const uint32 * const src0, uint32 * const dst0,
	const size_t size)
{
	const uint32 *src = src0;
	uint32 *dst = dst0, uc;
	size_t left = size;

	while (0x0000 != (uc = *src++)) {
		size_t n;

		n = utf32_case_fold_char(uc, dst, left);
		dst += n;
		left = left > n ? (left - n) : 0;
	}
	if (size > 0) {
		*dst = 0x0000;
	}
	return dst - dst0;
}

/**
 * Filters characters that are ignorable for query strings. *space
 * should be initialized to TRUE for the first character of a string.
 * ``space'' is used to prevent adding multiple space characters i.e.,
 * a space should not be followed by a space.
 *
 * @param uc an UTF-32 character
 * @param space pointer to a boolean holding the current space state
 * @param last should be TRUE if ``uc'' is the last character of the string.
 * @return	zero if the character should be skipped, otherwise the
 *			character itself or a replacement character.
 */
static inline uint32
utf32_filter_char(uint32 uc, bool *space, bool last)
{
	uni_gc_t gc;

	g_assert(space != NULL);

	if (utf32_is_non_character(uc))
		gc = UNI_GC_OTHER_PRIVATE_USE;	/* XXX: hack but good enough */
	else
		gc = utf32_general_category(uc);

	switch (gc) {
	case UNI_GC_LETTER_LOWERCASE:
	case UNI_GC_LETTER_OTHER:
	case UNI_GC_LETTER_MODIFIER:
	case UNI_GC_NUMBER_DECIMAL:
	case UNI_GC_OTHER_NOT_ASSIGNED:
		*space = FALSE;
		return uc;

	case UNI_GC_OTHER_CONTROL:
		if (uc == '\n')
			return uc;
		break;

	case UNI_GC_MARK_NONSPACING:
		/*
		 * Do not skip the japanese (U+3099) and (U+309A) kana marks and so on
		 */
		switch (uc) {
		/* Japanese voiced sound marks */
		case 0x3099:
		case 0x309A:
			/* Virama signs */
		case 0x0BCD:
		case 0x094D:
		case 0x09CD:
		case 0x0A4D:
		case 0x0ACD:
		case 0x0B4D:
		case 0x0CCD:
		case 0x1039:
		case 0x1714:
		case 0x0C4D:
			/* Nukta signs */
		case 0x093C:
		case 0x09BC:
		case 0x0A3C:
		case 0x0ABC:
		case 0x0B3C:
		case 0x0CBC:
			/* Greek Ypogegrammeni */
		case 0x0345:
			/* Tibetan */
		case 0x0F71:
		case 0x0F72:
		case 0x0F7A:
		case 0x0F7B:
		case 0x0F7C:
		case 0x0F7D:
		case 0x0F80:
		case 0x0F74:
		case 0x0F39:
		case 0x0F18:
		case 0x0F19:
		case 0x0F35:
		case 0x0F37:
		case 0x0FC6:
		case 0x0F82:
		case 0x0F83:
		case 0x0F84:
		case 0x0F86:
		case 0x0F87:

			/* Others : not very sure we must keep them or not ... */

			/* Myanmar */
		case 0x1037:
			/* Sinhala */
		case 0x0DCA:
			/* Thai */
		case 0x0E3A:
			/* Hanundo */
		case 0x1734:
			/* Devanagari */
		case 0x0951:
		case 0x0952:
			/* Lao */
		case 0x0EB8:
		case 0x0EB9:
			/* Limbu */
		case 0x193B:
		case 0x1939:
		case 0x193A:
			/* Mongolian */
		case 0x18A9:
			return uc;
		}
		break;

	case UNI_GC_PUNCT_OTHER:
	/* XXX: Disabled for backwards compatibility. Especially '.' is
	 *		problematic because filename extensions are not separated
	 *		from the rest of the name otherwise. Also, some people use
	 *		dots instead of spaces in filenames. */
#if 0
		if ('\'' == uc || '*' == uc || '.' == uc)
			return uc;
		/* FALLTHRU */
#endif

	case UNI_GC_LETTER_UPPERCASE:
	case UNI_GC_LETTER_TITLECASE:

	case UNI_GC_MARK_SPACING_COMBINE:
	case UNI_GC_MARK_ENCLOSING:

	case UNI_GC_SEPARATOR_PARAGRAPH:
	case UNI_GC_SEPARATOR_LINE:
	case UNI_GC_SEPARATOR_SPACE:

	case UNI_GC_NUMBER_LETTER:
	case UNI_GC_NUMBER_OTHER:

	case UNI_GC_OTHER_FORMAT:
	case UNI_GC_OTHER_PRIVATE_USE:
	case UNI_GC_OTHER_SURROGATE:

	case UNI_GC_PUNCT_DASH:
	case UNI_GC_PUNCT_OPEN:
	case UNI_GC_PUNCT_CLOSE:
	case UNI_GC_PUNCT_CONNECTOR:
	case UNI_GC_PUNCT_INIT_QUOTE:
	case UNI_GC_PUNCT_FINAL_QUOTE:

	case UNI_GC_SYMBOL_MATH:
	case UNI_GC_SYMBOL_CURRENCY:
	case UNI_GC_SYMBOL_MODIFIER:
	case UNI_GC_SYMBOL_OTHER:
		{
			bool prev = *space;

			*space = TRUE;
			return prev || last ? 0 : 0x0020;
		}
	}

	return 0;
}

/**
 * Remove all the non letter and non digit by looking the unicode symbol type
 * all other characters will be reduce to normal space
 * try to merge consecutive spaces at the same time
 * keep the important non spacing marks
 *
 * @param src an NUL-terminated UTF-32 string.
 * @param dst the output buffer to hold the modified UTF-32 string.
 * @param size the number of characters (not bytes!) dst can hold.
 * @return The length of the output string.
 */
static size_t
utf32_filter(const uint32 *src, uint32 *dst, size_t size)
{
	const uint32 *s;
	uint32 uc, *p;
	bool space = TRUE; /* prevent adding leading space */

	g_assert(src != NULL);
	g_assert(size == 0 || dst != NULL);
	g_assert(size <= INT_MAX);

	s = src;
	p = dst;

	if (size > 0) {
		uint32 *end;

		for (end = &dst[size - 1]; p != end && 0x0000 != (uc = *s); s++) {
			if (0 != (uc = utf32_filter_char(uc, &space, 0x0000 == s[1])))
				*p++ = uc;
		}
		*p = 0x0000;
	}

	while (0x0000 != (uc = *s++)) {
		if (0 != utf32_filter_char(uc, &space, 0x0000 == *s))
			p++;
	}

	return p - dst;
}

/**
 * Copies the NUL-terminated UTF-32 string ``src'' to ``dst'' inserting
 * an ASCII whitespace (U+0020) at every Unicode block change. If the
 * block change is caused by such a ASCII whitespace itself, no additional
 * space is inserted.
 *
 * @param src an NUL-terminated UTF-32 string.
 * @param dst the output buffer to hold the modified UTF-32 string.
 * @param size the number of characters (not bytes!) dst can hold.
 * @return The length of the output string.
 */
static size_t
utf32_split_blocks(const uint32 *src, uint32 *dst, size_t size)
{
	const uint32 *s;
	uint32 uc, last_uc, *p;
	uint last_id;

	g_assert(src != NULL);
	g_assert(size == 0 || dst != NULL);
	g_assert(size <= INT_MAX);

	s = src;
	p = dst;
	last_uc = s[0];
	last_id = utf32_block_id(s[0]);

	if (size > 0) {
		uint32 *end;

		for (end = &dst[size - 1]; p != end && 0x0000 != (uc = *s); s++) {
			bool change;
			uint id = utf32_block_id(uc);

			change = last_id != id && uc != 0x0020 && last_uc != 0x0020;
			last_uc = uc;
			last_id = id;

			if (change) {
				*p++ = 0x0020;
				if (end == p) {
					s++;
					break;
				}
			}
			*p++ = uc;
		}
		*p = 0x0000;
	}

	while (0x0000 != (uc = *s++)) {
		uint id = utf32_block_id(uc);

		p += (last_id != id && uc != 0x0020 && last_uc != 0x0020) ? 2 : 1;
		last_uc = uc;
		last_id = id;
	}

	return p - dst;
}


#if 0  /* xxxUSE_ICU */

/**
 * Convert a string from the locale encoding to internal ICU encoding (UTF-16)
 */
int
locale_to_icu_conv(const char *in, int lenin, UChar *out, int lenout)
{
	UErrorCode error = U_ZERO_ERROR;
	int r;

	g_assert(use_icu);
	r = ucnv_toUChars(conv_icu_locale, out, lenout, in, lenin, &error);

	return (error != U_ZERO_ERROR && error != U_BUFFER_OVERFLOW_ERROR) ? 0 : r;
}

/**
 * Convert a string from UTF-8 encoding to internal ICU encoding (UTF-16)
 */
int
utf8_to_icu_conv(const char *in, int lenin, UChar *out, int lenout)
{
	UErrorCode error = U_ZERO_ERROR;
	int r;

	g_assert(use_icu);
	r = ucnv_toUChars(conv_icu_utf8, out, lenout, in, lenin, &error);

	return (error != U_ZERO_ERROR && error != U_BUFFER_OVERFLOW_ERROR) ? 0 : r;
}

/**
 * Convert a string from ICU encoding (UTF-16) to UTF8 encoding (fast)
 */
int
icu_to_utf8_conv(const UChar *in, int lenin, char *out, int lenout)
{
	UErrorCode error = U_ZERO_ERROR;
	int r;

	g_assert(use_icu);
	r = ucnv_fromUChars(conv_icu_utf8, out, lenout, in, lenin, &error);

	return (error != U_ZERO_ERROR && error != U_BUFFER_OVERFLOW_ERROR &&
			error != U_STRING_NOT_TERMINATED_WARNING) ? 0 : r;
}

/**
 * Compact a string as specified in unicode
 */
int
unicode_NFC(const UChar *source, gint32 len, UChar *result, gint32 rlen)
{
	UErrorCode error = U_ZERO_ERROR;
	int r;

	g_assert(use_icu);
	r = unorm_normalize(source, len, UNORM_NFC, 0, result, rlen, &error);

	return (error != U_ZERO_ERROR && error != U_BUFFER_OVERFLOW_ERROR) ? 0 : r;
}

/**
 * Compact a string as specified in unicode
 */
int
unicode_NFKC(const UChar *source, gint32 len, UChar *result, gint32 rlen)
{
	UErrorCode error = U_ZERO_ERROR;
	int r;

	g_assert(use_icu);
	r = unorm_normalize(source, len, UNORM_NFKC, 0, result, rlen, &error);

	return (error != U_ZERO_ERROR && error != U_BUFFER_OVERFLOW_ERROR) ? 0 : r;
}

/**
 * Expand and K a string as specified in unicode
 * K will transform special character in the standard form
 * for instance : The large japanese space will be transform to a normal space
 */
int
unicode_NFKD(const UChar *source, gint32 len, UChar *result, gint32 rlen)
{
	UErrorCode error = U_ZERO_ERROR;
	int r;

	g_assert(use_icu);
	r = unorm_normalize (source, len, UNORM_NFKD, 0, result, rlen, &error);

	return (error != U_ZERO_ERROR && error != U_BUFFER_OVERFLOW_ERROR) ? 0 : r;
}

int
unicode_NFD(const UChar *source, gint32 len, UChar *result, gint32 rlen)
{
	UErrorCode error = U_ZERO_ERROR;
	int r;

	g_assert(use_icu);
	r = unorm_normalize (source, len, UNORM_NFD, 0, result, rlen, &error);

	return (error != U_ZERO_ERROR && error != U_BUFFER_OVERFLOW_ERROR) ? 0 : r;
}

/**
 * Upper case a string
 * This is usefull to transorm the german sset to SS
 * Note : this will not transform hiragana to katakana
 */
int
unicode_upper(const UChar *source, gint32 len, UChar *result, gint32 rlen)
{
	UErrorCode error = U_ZERO_ERROR;
	int r;

	g_assert(use_icu);
	r = u_strToUpper(result, rlen, source, len, NULL, &error);

	return (error != U_ZERO_ERROR && error != U_BUFFER_OVERFLOW_ERROR) ? 0 : r;
}

/**
 * Lower case a string
 */
int
unicode_lower(const UChar *source, gint32 len, UChar *result, gint32 rlen)
{
	UErrorCode error = U_ZERO_ERROR;
	int r;

	g_assert(use_icu);
	r = u_strToLower(result, rlen, source, len, NULL, &error);

	return (error != U_ZERO_ERROR && error != U_BUFFER_OVERFLOW_ERROR) ? 0 : r;
}

/**
 * Remove all the non letter and non digit by looking the unicode symbol type
 * all other characters will be reduce to normal space
 * try to merge continues spaces in the same time
 * keep the important non spacing marks
 */
int
unicode_filters(const UChar *source, gint32 len, UChar *result)
{
	int i, j;
	int space = 1;

	g_assert(use_icu);

	for (i = 0, j = 0; i < len; i++) {
		UChar uc = source[i];

		switch (u_charType(uc)) {
		case U_LOWERCASE_LETTER :
		case U_OTHER_LETTER :
		case U_MODIFIER_LETTER :
		case U_DECIMAL_DIGIT_NUMBER :
		case U_UNASSIGNED :
			result[j++] = uc;
			space = 0;
			break;

		case U_CONTROL_CHAR :
			if (uc == '\n')
				result[j++] = uc;
			break;

		case U_NON_SPACING_MARK :
			/* Do not skip the japanese " and ° kana marks and so on */

			switch (uc) {
				/* Japanese voiced sound marks */
			case 0x3099:
			case 0x309A:
				/* Virama signs */
			case 0x0BCD:
			case 0x094D:
			case 0x09CD:
			case 0x0A4D:
			case 0x0ACD:
			case 0x0B4D:
			case 0x0CCD:
			case 0x1039:
			case 0x1714:
			case 0x0C4D:
				/* Nukta signs */
			case 0x093C:
			case 0x09BC:
			case 0x0A3C:
			case 0x0ABC:
			case 0x0B3C:
			case 0x0CBC:
				/* Greek Ypogegrammeni */
			case 0x0345:
				/* Tibetan */
			case 0x0F71:
			case 0x0F72:
			case 0x0F7A:
			case 0x0F7B:
			case 0x0F7C:
			case 0x0F7D:
			case 0x0F80:
			case 0x0F74:
			case 0x0F39:
			case 0x0F18:
			case 0x0F19:
			case 0x0F35:
			case 0x0F37:
			case 0x0FC6:
			case 0x0F82:
			case 0x0F83:
			case 0x0F84:
			case 0x0F86:
			case 0x0F87:

		/* Others : not very sure we must keep them or not ... */

				/* Myanmar */
			case 0x1037:
				/* Sinhala */
			case 0x0DCA:
				/* Thai */
			case 0x0E3A:
				/* Hanundo */
			case 0x1734:
				/* Devanagari */
			case 0x0951:
			case 0x0952:
				/* Lao */
			case 0x0EB8:
			case 0x0EB9:
				/* Limbu */
			case 0x193B:
			case 0x1939:
			case 0x193A:
				/* Mongolian */
			case 0x18A9:
				result[j++] = uc;
			}
			break;

		case U_OTHER_PUNCTUATION :
			if (
				'\'' == uc || '*' == uc
#if 0
	/* XXX: Disabled for backwards compatibility. The ASCII dot '.' is
	 *		problematic because filename extensions are not separated
	 *		from the rest of the name otherwise. Also, some people use
	 *		dots instead of spaces in filenames. */
				|| '.' == uc
#endif
			) {
				result[j++] = uc;
				break;
			}
			/* FALLTHRU */

		case U_UPPERCASE_LETTER :
		case U_TITLECASE_LETTER :
		case U_PARAGRAPH_SEPARATOR :
		case U_COMBINING_SPACING_MARK :
		case U_LINE_SEPARATOR :
		case U_LETTER_NUMBER :
		case U_OTHER_NUMBER :
		case U_SPACE_SEPARATOR :
		case U_FORMAT_CHAR :
		case U_PRIVATE_USE_CHAR :
		case U_SURROGATE :
		case U_DASH_PUNCTUATION :
		case U_START_PUNCTUATION :
		case U_END_PUNCTUATION :
		case U_CONNECTOR_PUNCTUATION :
		case U_MATH_SYMBOL :
		case U_CURRENCY_SYMBOL :
		case U_MODIFIER_SYMBOL :
		case U_OTHER_SYMBOL :
		case U_INITIAL_PUNCTUATION :
		case U_FINAL_PUNCTUATION :
		case U_CHAR_CATEGORY_COUNT :
			if (0 == space && 0x0000 != source[i + 1])
				result[j++] = 0x0020;
			space = 1;
			break;
		}
	}
	return j;
}

/**
 * Apply the NFKD/NFC algo to have nomalized keywords
 * The string `in' MUST be valid UTF-8 or that function would return rubbish.
 */
char *
unicode_canonize(const char *in)
{
	UChar *qtmp1;
	UChar *qtmp2;
	int	len, maxlen;
	char *out;

	g_assert(use_icu);

	len = strlen(in);
	maxlen = (len + 1) * 6; /* Max 6 bytes for one char in utf8 */

	g_assert(utf8_is_valid_data(in, len));

	qtmp1 = (UChar *) g_malloc(maxlen * sizeof(UChar));
	qtmp2 = (UChar *) g_malloc(maxlen * sizeof(UChar));

	len = utf8_to_icu_conv(in, len, qtmp2, maxlen);
	len = unicode_NFKD(qtmp2, len, qtmp1, maxlen);
	len = unicode_upper(qtmp1, len, qtmp2, maxlen);
	len = unicode_lower(qtmp2, len, qtmp1, maxlen);
	len = unicode_filters(qtmp1, len, qtmp2);
	len = unicode_NFC(qtmp2, len, qtmp1, maxlen);

	out = g_malloc(len + 1);
	len = icu_to_utf8_conv(qtmp1, len, out, len);
	out[len] = '\0';

	G_FREE_NULL(qtmp1);
	G_FREE_NULL(qtmp2);

	return out;
}

#endif	/* xxxUSE_ICU */

/**
 * @return	TRUE if ICU was successfully initialized. If FALSE is returned
 *			none of the ICU-related functions must be used.
 */
bool
icu_enabled(void)
{
	return use_icu;
}

/*
 * Is the locale using the latin alphabet?
 */
bool
locale_is_latin(void)
{
	return latin_locale;
}

/**
 * Composes an UTF-32 encoded string in-place. The modified string
 * might be shorter but is never longer than the original string.
 *
 * NB:	We assume that a direct composition eliminates at most one
 *		character. Further, the string must be in canonical order.
 *
 * @param src an NUL-terminated UTF-32 string.
 * @return	the length in characters (not bytes!) of the possibly
 *			modified string.
 */
static size_t
utf32_compose(uint32 *src)
{
	uint32 *s, *p, *end, uc;

	g_assert(src != NULL);

	s = utf32_next_starter(src); /* Skip over initial combining marks */
	p = s;

	end = &s[utf32_strlen(s)];

	/* The end is determined in advance because a composition
	 * can cause a ``hole''. Instead of rejoining the string each time,
	 * the erased composite character is replaced with a NUL which is then
	 * skipped when scanning the same position again.
     */

	while (0 != (uc = *s)) {
		int last_cc;
		uint32 *q;

	retry:
		for (last_cc = -1, q = s; ++q != end; /* NOTHING */) {
			uint32 uc2, composite;
			int cc;

			if (0 == (uc2 = *q))	/* Skip already used characters */
				continue;

			cc = utf32_combining_class(uc2);
			composite = utf32_compose_char(uc, uc2);
			if (!composite) {
				if (cc == 0)
					break;
				last_cc = cc;
			} else {
				if (last_cc >= cc)
					break;

				*q = 0;			/* Erase used character */
				uc = composite;	/* Replace starter with composition */
				goto retry;		/* Retry with the new starter */
			}
		}
		*p++ = uc;

		/*
		 * Pick-up unused combining characters between s and q
		 */
		while (++s != q) {
			if (0 != (uc = *s))
				*p++ = uc;
		}
	}
	*p = 0x0000;

	return p - src;
}

/**
 */
static uint32 *
utf32_normalize(const uint32 *src, uni_norm_t norm)
{
	uint32 buf[1024], *dst;
	size_t size, n;
	bool compat = FALSE;
	bool ok = FALSE;

	g_assert(UNSIGNED(norm) < NUM_UNI_NORM);

	switch (norm) {
	case UNI_NORM_NFKC:
	case UNI_NORM_NFKD:
		compat = TRUE;
		/* FALLTHRU */
	case UNI_NORM_NFC:
	case UNI_NORM_NFD:
		ok = TRUE;
		break;

	case NUM_UNI_NORM:
		break;
	}
	if (!ok) {
		g_assert_not_reached();
		return NULL;
	}

	/* Decompose string to NFD or NFKD  */
	n = utf32_decompose(src, buf, N_ITEMS(buf), compat);
	size = n + 1;
	if (n < N_ITEMS(buf)) {
		dst = buf;
	} else {
		dst = g_malloc(size * sizeof *dst);
		n = utf32_decompose(src, dst, size, compat);
		g_assert(size - 1 == n);
	}

	switch (norm) {
	case UNI_NORM_NFC:
	case UNI_NORM_NFKC:
		{
			uint32 *ret;

			/* Compose string */
			n = utf32_compose(dst);
			n = utf32_compose_hangul(dst);
			ret = utf32_strdup(dst);
			if (buf != dst) {
				G_FREE_NULL(dst);
			}
			return ret;
		}

	case UNI_NORM_NFD:
	case UNI_NORM_NFKD:
		return dst != buf ? dst : utf32_strdup(buf);

	case NUM_UNI_NORM:
		break;
	}
	g_assert_not_reached();

	/* NOTREACHED */
	return NULL;
}

/**
 * Normalizes an UTF-8 string to the request normal form and returns
 * it as a newly allocated string.
 *
 * @param src the string to normalize, must be valid UTF-8.
 * @param norm one of UNI_NORM_NFC, UNI_NORM_NFD, UNI_NORM_NFKC, UNI_NORM_NFKD.
 *
 * @return a newly allocated string
 */
char *
utf8_normalize(const char *src, uni_norm_t norm)
{
	uint32 *dst32;

	g_assert(src);
	g_assert(utf8_is_valid_string(src));
	g_assert(UNSIGNED(norm) < NUM_UNI_NORM);

	if (is_ascii_string(src)) {
		/*
		 * Optimize this later and return the original src pointer.
		 */
		return g_strdup(src);
	} else {
		size_t n;
		uint32 buf[1024];
		uint32 *s;

		n = utf8_to_utf32(src, buf, N_ITEMS(buf));
		if (n < N_ITEMS(buf)) {
			s = buf;
		} else {
			size_t size = n + 1;

			s = g_malloc(size * sizeof *s);
			n = utf8_to_utf32(src, s, size);
			g_assert(size - 1 == n);
		}

		dst32 = utf32_normalize(s, norm);

		g_assert(dst32 != s);
		if (s != buf) {
			G_FREE_NULL(s);
		}
	}

	(void) utf32_to_utf8_inplace(dst32);
	return cast_to_char_ptr(dst32);
}

/**
 * Apply the NFKD/NFC algo to have nomalized keywords (string is halloc()-ed)
 */
static uint32 *
utf32_canonize(const uint32 *src0)
{
	uint32 *dst, *src;
	size_t size, n;

	/* Convert to NFC */
	size = utf32_strlen(src0) + 1;
	src = HCOPY_ARRAY(src0, size);
	(void) utf32_compose(src);

	/* Apply simple and special folding */
	n = utf32_case_fold(src, NULL, 0);
	size = n + 1;
	HALLOC_ARRAY(dst, size);
	n = utf32_case_fold(src, dst, size);
	HFREE_NULL(src);
	src = dst;

	/* Convert to NFKD */
	n = utf32_decompose(src, NULL, 0, TRUE);
	size = n + 1;
	HALLOC_ARRAY(dst, size);
	n = utf32_decompose(src, dst, size, TRUE);
	g_assert(size - 1 == n);
	HFREE_NULL(src);
	src = dst;

	/* Apply special filter; works in-place */
	n = utf32_filter(src, src, size);
	g_assert(size - 1 >= n);

	/* Convert to NFD; this might be unnecessary if the previous
	 * operations did not destroy the NFKD */
	n = utf32_decompose(src, NULL, 0, FALSE);
	size = n + 1;
	HALLOC_ARRAY(dst, size);
	n = utf32_decompose(src, dst, size, FALSE);
	g_assert(size - 1 == n);
	HFREE_NULL(src);
	src = dst;

	/* Convert to NFC; works in-place */
	n = utf32_compose(src);
	n = utf32_compose_hangul(src);

	/* Insert an ASCII space at block changes, this keeps NFC */
	n = utf32_split_blocks(src, NULL, 0);
	size = n + 1;
	HALLOC_ARRAY(dst, size);
	n = utf32_split_blocks(src, dst, size);
	g_assert(size - 1 == n);
	HFREE_NULL(src);

	return dst;
}

/**
 * Apply the NFKD/NFC algo to have nomalized keywords (string is halloc()-ed)
 */
char *
utf8_canonize(const char *src)
{
	uint32 *dst32;

	g_assert(utf8_is_valid_string(src));

	{
		size_t n;
		uint32 buf[1024];
		uint32 *s;

		n = utf8_to_utf32(src, buf, N_ITEMS(buf));
		if (n < N_ITEMS(buf)) {
			s = buf;
		} else {
			size_t size = n + 1;

			HALLOC_ARRAY(s, size);
			n = utf8_to_utf32(src, s, size);
			g_assert(size - 1 == n);
		}

		dst32 = utf32_canonize(s);
		g_assert(dst32 != s);
		if (s != buf) {
			HFREE_NULL(s);
		}
	}

	(void) utf32_to_utf8_inplace(dst32);
	return cast_to_char_ptr(dst32);
}

/**
 * Helper function to sort the lists of ``utf32_compose_roots''.
 */
static int
compose_root_cmp(const void *a, const void *b)
{
	uint i = GPOINTER_TO_UINT(a), j = GPOINTER_TO_UINT(b);

	g_assert(i < N_ITEMS(utf32_nfkd_lut));
	g_assert(j < N_ITEMS(utf32_nfkd_lut));
	return CMP(utf32_nfkd_lut[i].d[1], utf32_nfkd_lut[j].d[1]);
}

/**
 * This is a helper for unicode_compose_init() to create the lookup
 * table used by utf32_compose_char(). The first character of the
 * decomposition sequence is used as key, the index into the
 * ``utf32_nfkd_lut'' is used as value.
 */
static void
unicode_compose_add(uint idx)
{
	pslist_t *sl, *new_sl;
	void *key;

	key = GUINT_TO_POINTER(utf32_nfkd_lut[idx].d[0]);
	sl = htable_lookup(utf32_compose_roots, key);
	new_sl = pslist_insert_sorted(sl, uint_to_pointer(idx), compose_root_cmp);
	if (sl != new_sl)
		htable_insert(utf32_compose_roots, key, new_sl);
}

static void G_COLD
unicode_compose_init(void)
{
	size_t i;

	/* Check order and consistency of the general category lookup table */
	for (i = 0; i < N_ITEMS(utf32_general_category_lut); i++) {
		size_t len;
		uint32 uc;
		uni_gc_t gc;

		uc = utf32_general_category_lut[i].uc;
		gc = utf32_general_category_lut[i].gc;
		len = utf32_general_category_lut[i].len;

		g_assert(len > 0); /* entries are at least one character large */

		if (i > 0) {
			size_t prev_len;
			uint32 prev_uc;
			uni_gc_t prev_gc;

			prev_uc = utf32_general_category_lut[i - 1].uc;
			prev_gc = utf32_general_category_lut[i - 1].gc;
			prev_len = utf32_general_category_lut[i - 1].len;

			g_assert(prev_uc < uc);	/* ordered */
			g_assert(prev_uc + prev_len <= uc); /* non-overlapping */
			/* The category must changed with each entry, unless
			 * there's a gap */
			g_assert(prev_gc != gc || prev_uc + prev_len < uc);
		}

		do {
			g_assert(gc == utf32_general_category(uc));
			uc++;
		} while (--len != 0);
	}

	/* Check order and consistency of the composition exclusions table */
	for (i = 0; i < N_ITEMS(utf32_composition_exclusions); i++) {
		uint32 uc;

		uc = utf32_composition_exclusions[i];
		g_assert(i == 0 || uc > utf32_composition_exclusions[i - 1]);
		g_assert(utf32_composition_exclude(uc));
	}

	/* Check order and consistency of the block ID lookup table */
	for (i = 0; i < N_ITEMS(utf32_block_id_lut); i++) {
		uint32 start, end;

		start = utf32_block_id_lut[i].start;
		end = utf32_block_id_lut[i].end;
		g_assert(start <= end);
		g_assert(0 == i || utf32_block_id_lut[i - 1].end < start);
		g_assert(1 + i == utf32_block_id(start));
		g_assert(1 + i == utf32_block_id(end));
	}

	/* Create the composition lookup table */
	utf32_compose_roots = htable_create(HASH_KEY_SELF, 0);

	for (i = 0; i < N_ITEMS(utf32_nfkd_lut); i++) {
		uint32 uc;

		uc = utf32_nfkd_lut[i].c;

		g_assert(i == 0 ||
			(uc & ~UTF32_F_MASK) > (utf32_nfkd_lut[i - 1].c & ~UTF32_F_MASK));

		if (!(uc & UTF32_F_NFKD)) {
			const uint32 *s;

			uc &= ~UTF32_F_MASK;
			s = utf32_decompose_lookup(uc, FALSE);
			g_assert(s);
			g_assert(s[0] != 0);

			/* Singletons are excluded from compositions */
			if (0 == s[1])
				continue;

			/* Decomposed sequences beginning with a non-starter are excluded
	 		 * from compositions */
			if (0 != utf32_combining_class(s[0]))
				continue;

			/* Special exclusions */
			if (utf32_composition_exclude(uc))
				continue;

			/* NB:	utf32_compose() assumes that each direct composition
	 		 *		eliminates at most one character.
			 */
			g_assert(s[0] != 0 && s[1] != 0 && s[2] == 0);

			unicode_compose_add(i);
		}
	}

	unicode_compose_init_passed = TRUE;
}

static const char *
utf8_latinize_char(const uint32 uc)
{
#define GET_ITEM(i)	(jap_tab[(i)].uc)
#define FOUND(i)	return jap_tab[(i)].s

	BINARY_SEARCH(uint32, uc, N_ITEMS(jap_tab), CMP, GET_ITEM, FOUND);

#undef FOUND
#undef GET_ITEM

	return NULL;
}

static const char *
utf8_latinize_chars(const uint32 uc, const uint32 next, bool *used_next)
{
	switch (next) {
	/* Hiragana combines */
	case 0x3083:	/* ya */
	case 0x3084:	/* YA */
	case 0x3085:	/* yu */
	case 0x3086:	/* YU */
	case 0x3087:	/* yo */
	case 0x3088:	/* YO */
	/* Katakana combines */
	case 0x30E3:	/* ya */
	case 0x30E4:	/* YA */
	case 0x30E5:	/* yu */
	case 0x30E6:	/* YU */
	case 0x30E7:	/* yo */
	case 0x30E8:	/* YO */
		{
			static const char map[] =
				"kya\0"  "kyu\0"  "kyo\0"	/* 0 */
				"sha\0"  "shu\0"  "sho\0"	/* 1 */
				"cha\0"  "chu\0"  "cho\0"	/* 2 */
				"nya\0"  "nyu\0"  "nyo\0"	/* 3 */
				"hya\0"  "hyu\0"  "hyo\0"	/* 4 */
				"mya\0"  "myu\0"  "myo\0"	/* 5 */
				"rya\0"  "ryu\0"  "ryo\0"	/* 6 */
				"gya\0"  "gyu\0"  "gyo\0"	/* 7 */
				"ja\0\0" "ju\0\0" "jo\0\0"	/* 8 */
				"bya\0"  "byu\0"  "byo\0"	/* 9 */
				"pya\0"  "pyu\0"  "pyo\0";	/* A */
			unsigned offset;

			STATIC_ASSERT(sizeof map == 12 * 11 + 1);

			switch (uc){
			case 0x304D: case 0x30AD: offset =  0 * 12; break; /* ky */
			case 0x3057: case 0x30B7: offset =  1 * 12; break; /* sh */
			case 0x3061: case 0x30C1: offset =  2 * 12; break; /* ch */
			case 0x306B: case 0x30CB: offset =  3 * 12; break; /* ny */
			case 0x3072: case 0x30D2: offset =  4 * 12; break; /* hy */
			case 0x307F: case 0x30DF: offset =  5 * 12; break; /* my */
			case 0x308A: case 0x30EA: offset =  6 * 12; break; /* ry */
			case 0x304E: case 0x30AE: offset =  7 * 12; break; /* gy */
			case 0x3058: case 0x30B8: offset =  8 * 12; break; /* j  */
			case 0x3073: case 0x30D3: offset =  9 * 12; break; /* by */
			case 0x3074: case 0x30D4: offset = 10 * 12; break; /* py */
			default:	 goto finish;
			}
			offset += (next - ((next & 0x30E0) | 3)) / 2;
			*used_next = TRUE;
			return &map[offset];
		}
	}

finish:
	*used_next = FALSE;
	return utf8_latinize_char(uc);
}

/**
 * Checks whether the given UTF-8 string contains any convertible
 * characters.
 *
 * @param src an UTF-8 encoded NUL-terminated string.
 * @return TRUE if utf8_latinize() would convert any characters;
 *         otherwise FALSE.
 */
bool
utf8_can_latinize(const char *src)
{
	uint retlen;
	uint32 uc;

	g_assert(NULL != src);

	while (0x0000 != (uc = utf8_decode_char_fast(src, &retlen))) {
		if (utf8_latinize_char(uc))
			return TRUE;
		src += retlen;
	}

	return FALSE;
}

/**
 * Converts hiragana and katakana characters to ASCII sequences,
 * strips voice marks and keeps any other characters as is. The conversion
 * result is not correct romaji, hence the term "latinize".
 *
 * @param dst the destination buffer.
 * @param dst_size the size of the dst buffer in bytes.
 * @param src the source string.
 * @return The length in bytes of the resulting string assuming
 *         dst_size was sufficient.
 */
size_t
utf8_latinize(char *dst, const size_t dst_size, const char *src)
{
	char *d = dst;
	const char *s = src;
	size_t left;

	g_assert(0 == dst_size || NULL != dst);
	g_assert(NULL != src);

	left = dst_size;
	while ('\0' != *s) {
		uint retlen, next_len;
		const char *r;
		size_t r_len;
		uint32 uc, next;
		bool used_next;

		uc = utf8_decode_char_fast(s, &retlen);
		if (!uc)
			break;

		next = utf8_decode_char_fast(&s[retlen], &next_len);
		r = utf8_latinize_chars(uc, next, &used_next);
		if (r) {
			r_len = strlen(r);
		} else {
			r = s;
			r_len = retlen;
		}
		if (r_len >= left) {
			left = 0;
		} else {
			memmove(d, r, r_len);
			left -= r_len;
		}
		s += retlen + (used_next ? next_len : 0);
		d += r_len;
	}
	if (dst_size > 0) {
		*d = '\0';
	}
	return d - dst;
}

#if defined(TEST_NORMALIZATION_TEST_TXT)
/**
 * Checks all cases listed in NormalizationTest.txt. This does not take
 * very long but the table is pretty huge.
 */
static void G_COLD
regression_normalization_test_txt(void)
{
	size_t i;

	for (i = 0; i < N_ITEMS(normalization_test_txt); i++) {
		const uint32 *c[6];
		size_t j;

		/*
		 * Skip 0 for better readability because NormalizationTest.txt
		 * refers to the columns as c1..c5.
		 */
		c[0] = NULL;
		for (j = 1; j < N_ITEMS(c); j++) {
			const uint32 *src;
			uint32 buf[256];
			uchar chars[256];
			size_t len, n;

			src = normalization_test_txt[i].c[j - 1];
			len = utf32_to_utf8(src, chars, sizeof chars);
			g_assert(len > 0);
			g_assert(len < sizeof chars);
			n = utf8_to_utf32(chars, buf, N_ITEMS(buf));
			g_assert(n == utf32_strlen(src));
			g_assert(0 == utf32_strcmp(src, buf));

			c[j] = src;
		}

		{
			uint32 *nfc;

			/* c2 == NFC(c1) */
			nfc = utf32_normalize(c[1], UNI_NORM_NFC);
			g_assert(0 == utf32_strcmp(c[2], nfc));
			G_FREE_NULL(nfc);

			/* c2 == NFC(c2) */
			nfc = utf32_normalize(c[2], UNI_NORM_NFC);
			g_assert(0 == utf32_strcmp(c[2], nfc));
			G_FREE_NULL(nfc);

			/* c2 == NFC(c3) */
			nfc = utf32_normalize(c[3], UNI_NORM_NFC);
			g_assert(0 == utf32_strcmp(c[2], nfc));
			G_FREE_NULL(nfc);

			/* c4 == NFC(c4) */
			nfc = utf32_normalize(c[4], UNI_NORM_NFC);
			g_assert(0 == utf32_strcmp(c[4], nfc));
			G_FREE_NULL(nfc);

			/* c4 == NFC(c5) */
			nfc = utf32_normalize(c[5], UNI_NORM_NFC);
			g_assert(0 == utf32_strcmp(c[4], nfc));
			G_FREE_NULL(nfc);
		}

		{
			uint32 *nfd;

			/* c3 == NFD(c1) */
			nfd = utf32_normalize(c[1], UNI_NORM_NFD);
			g_assert(0 == utf32_strcmp(c[3], nfd));
			G_FREE_NULL(nfd);

			/* c3 == NFD(c2) */
			nfd = utf32_normalize(c[2], UNI_NORM_NFD);
			g_assert(0 == utf32_strcmp(c[3], nfd));
			G_FREE_NULL(nfd);

			/* c3 == NFD(c3) */
			nfd = utf32_normalize(c[3], UNI_NORM_NFD);
			g_assert(0 == utf32_strcmp(c[3], nfd));
			G_FREE_NULL(nfd);

			/* c5 == NFD(c4) */
			nfd = utf32_normalize(c[4], UNI_NORM_NFD);
			g_assert(0 == utf32_strcmp(c[5], nfd));
			G_FREE_NULL(nfd);

			/* c5 == NFD(c5) */
			nfd = utf32_normalize(c[5], UNI_NORM_NFD);
			g_assert(0 == utf32_strcmp(c[5], nfd));
			G_FREE_NULL(nfd);
		}

		{
			uint32 *nfkc;

			/* c4 == NFKC(c1) */
			nfkc = utf32_normalize(c[1], UNI_NORM_NFKC);
			g_assert(0 == utf32_strcmp(c[4], nfkc));
			G_FREE_NULL(nfkc);

			/* c4 == NFKC(c2) */
			nfkc = utf32_normalize(c[2], UNI_NORM_NFKC);
			g_assert(0 == utf32_strcmp(c[4], nfkc));
			G_FREE_NULL(nfkc);

			/* c4 == NFKC(c3) */
			nfkc = utf32_normalize(c[3], UNI_NORM_NFKC);
			g_assert(0 == utf32_strcmp(c[4], nfkc));
			G_FREE_NULL(nfkc);

			/* c4 == NFKC(c4) */
			nfkc = utf32_normalize(c[4], UNI_NORM_NFKC);
			g_assert(0 == utf32_strcmp(c[4], nfkc));
			G_FREE_NULL(nfkc);

			/* c4 == NFKC(c5) */
			nfkc = utf32_normalize(c[5], UNI_NORM_NFKC);
			g_assert(0 == utf32_strcmp(c[4], nfkc));
			G_FREE_NULL(nfkc);
		}

		{
			uint32 *nfkd;

			/* c5 == NFKD(c1) */
			nfkd = utf32_normalize(c[1], UNI_NORM_NFKD);
			g_assert(0 == utf32_strcmp(c[5], nfkd));
			G_FREE_NULL(nfkd);

			/* c5 == NFKD(c2) */
			nfkd = utf32_normalize(c[2], UNI_NORM_NFKD);
			g_assert(0 == utf32_strcmp(c[5], nfkd));
			G_FREE_NULL(nfkd);

			/* c5 == NFKD(c3) */
			nfkd = utf32_normalize(c[3], UNI_NORM_NFKD);
			g_assert(0 == utf32_strcmp(c[5], nfkd));
			G_FREE_NULL(nfkd);

			/* c5 == NFKD(c4) */
			nfkd = utf32_normalize(c[4], UNI_NORM_NFKD);
			g_assert(0 == utf32_strcmp(c[5], nfkd));
			G_FREE_NULL(nfkd);

			/* c5 == NFKD(c5) */
			nfkd = utf32_normalize(c[5], UNI_NORM_NFKD);
			g_assert(0 == utf32_strcmp(c[5], nfkd));
			G_FREE_NULL(nfkd);
		}
	}
}
#endif /* TEST_NORMALIZATION_TEST_TXT */

/**
 * Checks that the following holds except for the characters
 * the appear in column 1 in Part 1 of NormalizationTest.txt:
 *
 * X == NFC(X) == NFD(X) == NFKC(X) == NFKD(X)
 */
static void G_COLD
regression_normalization_character_identity(void)
{
	size_t i;

	for (i = 0; i < 0x10FFFF; i++) {
		static uint32 s[2];
		uint32 *nfc, *nfd, *nfkc, *nfkd;

		if (utf32_bad_codepoint(i) || utf32_is_normalization_special(i))
			continue;

		s[0] = i;
		nfc = utf32_normalize(s, UNI_NORM_NFC);
		nfd = utf32_normalize(s, UNI_NORM_NFD);
		nfkc = utf32_normalize(s, UNI_NORM_NFKC);
		nfkd = utf32_normalize(s, UNI_NORM_NFKD);
		g_assert(0 == utf32_strcmp(s, nfc));
		g_assert(0 == utf32_strcmp(s, nfd));
		g_assert(0 == utf32_strcmp(s, nfkc));
		g_assert(0 == utf32_strcmp(s, nfkd));
		G_FREE_NULL(nfc);
		G_FREE_NULL(nfd);
		G_FREE_NULL(nfkc);
		G_FREE_NULL(nfkd);
	}
}

/**
 * See: http://www.unicode.org/review/pr-29.html
 */
static void G_COLD
regression_normalization_issue(void)
{
	static const struct {
		uint32 s[8];
	} tests[] = {
		{ { 0x0b47, 0x0300, 0x0b3e, 0 } },
		{ { 0x1100, 0x0300, 0x1161, 0 } },
		{ { 0x1100, 0x0300, 0x1161, 0x0323, 0 } },
	};
	uint i;

	for (i = 0; i < N_ITEMS(tests); i++) {
		uint32 *s, *t;
		bool eq;

		s = utf32_normalize(tests[i].s, UNI_NORM_NFC);
		eq = 0 == utf32_strcmp(s, tests[i].s);
		g_assert(eq);

		t = utf32_normalize(s, UNI_NORM_NFC);
		eq = 0 == utf32_strcmp(t, tests[i].s);
		g_assert(eq);

		G_FREE_NULL(s);
		G_FREE_NULL(t);
	}
}

static void G_COLD
regression_utf8_strlower(void)
{
	{
		const char blah[] = "some lowercase ascii";
		char buf[sizeof blah];
		size_t len;

		len = utf8_strlower(buf, blah, sizeof buf);
		g_assert(len == CONST_STRLEN(blah));
		g_assert(0 == strcmp(blah, buf));
		g_assert(len == utf8_char_count(blah));
		g_assert(len == utf8_strlen(blah));
	}

	{
		const uchar s[] = {
			0xc3, 0xb6, 0xc3, 0xa4, 0xc3, 0xb6, 0xc3, 0xa4, 0xc3,
			0xb6, 0xc3, 0xb6, 0xc3, 0xb6, 0xc3, 0xb6, 0xc3, 0xbc, 0x0,
		};
		size_t len, size;
		char *dst;
		const char *src = cast_to_constpointer(s);

		len = utf8_strlower(NULL, src, 0);
		size = len + 1;
		dst = g_malloc(size);
		len = utf8_strlower(dst, src, size);
		g_assert(len == size - 1);
		g_assert(utf8_strlen(dst) == utf8_strlen(src));
		g_assert(utf8_strlen(dst) == utf8_char_count(dst));
		G_FREE_NULL(dst);
	}
}

/**
 * The following code is supposed to reproduce bug #1211413.
 */
static void
regression_bug_1211413(void)
{
	static const char bad[] = "\201y\223\220\216B\201znaniwa "
		"\224\xfc\217\217\227\202\xcc\220\xab "
		"\202\xb5\202\xcc"
		"18\215\xce\201@\202d\203J\203b\203v.mpg";
	const char *s;
	size_t len, chars;
	uint32 *u;

	s = lazy_locale_to_utf8_normalized(bad, UNI_NORM_NFC);
	len = strlen(s);
	chars = utf8_char_count(s);
	g_assert(len != 0);
	g_assert(len >= chars);
	len = utf8_to_utf32(s, NULL, 0);
	g_assert(len <= chars);
	u = g_malloc0((len + 1) * sizeof *u);
	utf8_to_utf32(s, u, len + 1);
	G_FREE_NULL(u);
}

/**
 * Some iconv()s let invalid UTF-8 with codepoints
 * beyond U+10FFFF slip through, when converting from UTF-8 to UTF-8.
 * Thus, use utf8_enforce() for UTF-8 -> UTF-8 instead.
 */
static void
regression_iconv_utf8_to_utf8(void)
{
	const uchar s[] = {
		0xa1, 0xbe, 0xb4, 0xba, 0xc7, 0xef, 0xd3, 0xe9, 0xc0, 0xd6, 0xd6,
		0xc6, 0xd7, 0xf7, 0xa1, 0xbf, 0xb3, 0xfe, 0xc3, 0xc5, 0xb5, 0xc4,
		0xca, 0xc0, 0xbd, 0xe7, 0x0
	};

	(void) lazy_locale_to_utf8_normalized(cast_to_constpointer(s),
				UNI_NORM_NFC);
}

/**
 * Verify that each UTF-8 encoded codepoint is decoded to the same
 * codepoint.
 */
static void G_COLD
regression_utf8_bijection(void)
{
	uint32 uc;

	for (uc = 0; uc <= 0x10FFFF; uc++) {
		static char utf8_char[4];
		uint len, len1;
		uint32 uc1;

		len = utf8_encode_char(uc, utf8_char, sizeof utf8_char);
		if (!len)
			continue;
		g_assert(len > 0 && len <= 4);

		uc1 = utf8_decode_char_fast(utf8_char, &len1);
		g_assert_log(uc == uc1 && len == len1,
			"uc=%x uc1=%x, len=%d, len1=%d", uc, uc1, len, len1);

#if defined(TEST_UTF8_DECODER)
		{
			uint32 uc2;
			uint len2;

			uc2 = utf8_decode_char_less_fast(utf8_char, &len2);
			g_assert(uc1 == uc2);
			g_assert(len1 == len2);
		}
#endif /* TEST_UTF8_DECODER */
	}
}

/**
 * Verify that unknown_to_utf8() works for some test cases.
 * NOTE: Because unknown_to_utf8() falls back to the locale, the output
 *		 can differ. Thus it only checks whether it crashes or not.
 */
static void
regression_utf8_unknown_conversion(void)
{
	const char *input = "\xe6\x3f\x8b\x20\xe3\x3f\x99\xe3"
		"\x82\x8b\x20\xe3\x82\xb7\xe3\x3f\xb9";
	const char *output;

	output = unknown_to_utf8(input, NULL);
	g_assert(output);
}

#if defined(TEST_UTF8_DECODER)
/**
 * Check utf8_decode_char_fast() for all 4-byte combinations. This
 * takes about 3 minutes of CPU time on an Athlon Duron 1.4GHz.
 */
static void G_COLD
regression_utf8_decoder(void)
{
	uint32 uc = 0;

	do {
		uint len1, len2;
		uint32 uc1, uc2;

		uc1 = utf8_decode_char_fast(cast_to_constpointer(&uc), &len1);
		uc2 = utf8_decode_char_less_fast(cast_to_constpointer(&uc), &len2);

#if 0
		g_debug("uc=%08X uc1=%x, uc2=%x, len1=%u, len2=%u",
			uc, uc1, uc2, len1, len2);
#endif

		g_assert(!UNICODE_IS_ILLEGAL(uc1));
		g_assert(uc1 == uc2);
		g_assert(len1 == len2);

		if (0 != len1) {
			static char utf8_char[4];
			uint len;
			bool eq;

			len = utf8_encode_char(uc1, utf8_char, sizeof utf8_char);
			g_assert(len1 == len);
			eq = 0 == memcmp(cast_to_constpointer(&uc), utf8_char, len);
			g_assert(eq);
		}
	} while (0 != ++uc); /* while (!0xc0ffee) */
}
#endif /* TEST_UTF8_DECODER */

#ifdef UNICODE_VERSUS_GLIB_REGRESSION
/**
 * The following checks are broken as GLib does not implement Unicode 4.1.0
 * at the moment. --cbiere, 2005-08-02
 */
static void G_COLD
regression_utf8_vs_glib2(void)
{
#if defined(USE_GLIB2)
	size_t i;

	for (i = 0; i <= 0x10FFFD; i++) {
		uint32 uc;
		GUnicodeType gt;

		uc = i;
		gt = g_unichar_type(uc);
		g_debug("uc=U+%04X", (uint) uc);
		switch (utf32_general_category(uc)) {
		case UNI_GC_LETTER_UPPERCASE:
			g_assert(G_UNICODE_UPPERCASE_LETTER == gt);
			break;
		case UNI_GC_LETTER_LOWERCASE:
			g_assert(G_UNICODE_LOWERCASE_LETTER == gt);
			break;
		case UNI_GC_LETTER_TITLECASE:
			g_assert(G_UNICODE_TITLECASE_LETTER == gt);
			break;
		case UNI_GC_LETTER_MODIFIER:
			g_assert(G_UNICODE_MODIFIER_LETTER == gt);
			break;
		case UNI_GC_LETTER_OTHER:
			g_assert(G_UNICODE_OTHER_LETTER == gt);
			break;
		case UNI_GC_MARK_NONSPACING:
			g_assert(G_UNICODE_NON_SPACING_MARK == gt);
			break;
		case UNI_GC_MARK_SPACING_COMBINE:
			g_assert(G_UNICODE_COMBINING_MARK == gt);
			break;
		case UNI_GC_MARK_ENCLOSING:
			g_assert(G_UNICODE_ENCLOSING_MARK == gt);
			break;
		case UNI_GC_NUMBER_DECIMAL:
			g_assert(G_UNICODE_DECIMAL_NUMBER == gt);
			break;
		case UNI_GC_NUMBER_LETTER:
			g_assert(G_UNICODE_LETTER_NUMBER == gt);
			break;
		case UNI_GC_NUMBER_OTHER:
			g_assert(G_UNICODE_OTHER_NUMBER == gt);
			break;
		case UNI_GC_PUNCT_CONNECTOR:
			g_assert(G_UNICODE_CONNECT_PUNCTUATION == gt);
			break;
		case UNI_GC_PUNCT_DASH:
			g_assert(G_UNICODE_DASH_PUNCTUATION == gt);
			break;
		case UNI_GC_PUNCT_OPEN:
			g_assert(G_UNICODE_OPEN_PUNCTUATION == gt);
			break;
		case UNI_GC_PUNCT_CLOSE:
			g_assert(G_UNICODE_CLOSE_PUNCTUATION == gt);
			break;
		case UNI_GC_PUNCT_INIT_QUOTE:
			g_assert(G_UNICODE_INITIAL_PUNCTUATION == gt);
			break;
		case UNI_GC_PUNCT_FINAL_QUOTE:
			g_assert(G_UNICODE_FINAL_PUNCTUATION == gt);
			break;
		case UNI_GC_PUNCT_OTHER:
			g_assert(G_UNICODE_OTHER_PUNCTUATION == gt);
			break;
		case UNI_GC_SYMBOL_MATH:
			g_assert(G_UNICODE_MATH_SYMBOL == gt);
			break;
		case UNI_GC_SYMBOL_CURRENCY:
			g_assert(G_UNICODE_CURRENCY_SYMBOL == gt);
			break;
		case UNI_GC_SYMBOL_MODIFIER:
			g_assert(G_UNICODE_MODIFIER_SYMBOL == gt);
			break;
		case UNI_GC_SYMBOL_OTHER:
			g_assert(G_UNICODE_OTHER_SYMBOL == gt);
			break;
		case UNI_GC_SEPARATOR_SPACE:
			g_assert(G_UNICODE_SPACE_SEPARATOR == gt);
			break;
		case UNI_GC_SEPARATOR_LINE:
			g_assert(G_UNICODE_LINE_SEPARATOR == gt);
			break;
		case UNI_GC_SEPARATOR_PARAGRAPH:
			g_assert(G_UNICODE_PARAGRAPH_SEPARATOR == gt);
			break;
		case UNI_GC_OTHER_CONTROL:
			g_assert(G_UNICODE_CONTROL == gt);
			break;
		case UNI_GC_OTHER_FORMAT:
			g_assert(G_UNICODE_FORMAT == gt);
			break;
		case UNI_GC_OTHER_SURROGATE:
			g_assert(G_UNICODE_SURROGATE == gt);
			break;
		case UNI_GC_OTHER_PRIVATE_USE:
			g_assert(G_UNICODE_PRIVATE_USE == gt);
			break;
		case UNI_GC_OTHER_NOT_ASSIGNED:
			g_assert(G_UNICODE_UNASSIGNED == gt);
			break;
		}
	}

	for (;;) {
		uint32 test[32];
		uint32 q[1024], *x, *y;
		char s[1024], t[1024], *s_nfc;
		size_t size;

		for (i = 0; i < N_ITEMS(test) - 1; i++) {
			uint32 uc;

			do {
				uc = random_value(0x10FFFF);
			} while (
				!uc ||
				UNICODE_IS_SURROGATE(uc) ||
				UNICODE_IS_BYTE_ORDER_MARK(uc) ||
				UNICODE_IS_ILLEGAL(uc)
			);
			test[i] = uc;
		}
		test[i] = 0;

#if 0
		test[0] = 0x3271;
		test[1] = 0x26531;
		test[2] = 0;
#endif

#if 0
		test[0] = 0x1ed;
	   	test[1] = 0x945e4;
		test[2] = 0;
#endif

#if 0
		test[0] = 0x00a8;
	   	test[1] = 0x0711;
		test[2] = 0x301;
		test[3] = 0;
#endif

#if 0
		test[0] = 0xef0b8;
		test[1] = 0x56ecd;
	   	test[2] = 0x6b325;
	   	test[3] = 0x46fe6;
	   	test[4] = 0;
#endif

#if 0
		test[0] = 0x40d;
		test[1] = 0x3d681;
	   	test[2] = 0x1087ae;
	   	test[3] = 0x61ba1;
	   	test[4] = 0;
#endif

#if 0
		test[0] = 0x32b;
		test[1] = 0x93c;
	   	test[2] = 0x22f0;
	   	test[3] = 0xcb90;
	   	test[4] = 0;
#endif

#if 0
		/* This fails with GLib 2.6.0 because g_utf8_normalize()
		 * eats the Hangul Jamo character when using G_NORMALIZE_NFC. */
		test[0] = 0x1112;
		test[1] = 0x1174;
	   	test[2] = 0x11a7;
	   	test[3] = 0;
#endif

		size = 1 + utf32_decompose_nfkd(test, NULL, 0);
		y = g_malloc(size * sizeof *y);
		utf32_decompose_nfkd(test, y, size);
		x = utf32_strdup(y);
		utf32_compose(x);
		utf32_compose_hangul(x);
		utf32_to_utf8(x, t, sizeof t);

		utf32_to_utf8(test, s, sizeof s);

#if 1  /* !defined(xxxUSE_ICU) */
		s_nfc = g_utf8_normalize(s, (gssize) -1, G_NORMALIZE_NFKC);
#else
		{
			size_t len, maxlen;
			UChar *qtmp1, *qtmp2;

			maxlen = strlen(s) * 6 + 1;
			qtmp1 = (UChar *) g_malloc(maxlen * sizeof(UChar));
			qtmp2 = (UChar *) g_malloc(maxlen * sizeof(UChar));
			len = utf8_to_icu_conv(s, strlen(s), qtmp1, maxlen);
			len = unicode_NFC(qtmp1, len, qtmp2, maxlen);
			s_nfc = g_malloc0((len * 6) + 1);
			len = icu_to_utf8_conv(qtmp2, len, s_nfc, len * 6);
			s_nfc[len] = '\0';
			G_FREE_NULL(qtmp2);
			G_FREE_NULL(qtmp1);
		}
#endif

		g_assert(s_nfc != NULL);
		utf8_to_utf32(s_nfc, q, N_ITEMS(q));

		if (0 != strcmp(s_nfc, t))
			G_BREAKPOINT();

		G_FREE_NULL(x);
		G_FREE_NULL(y);
		G_FREE_NULL(s_nfc);
	}


	/* Check all single Unicode characters */
	for (i = 0; i <= 0x10FFFF; i++) {
		uint size;
		char buf[256];
		char utf8_char[6];	/* GLib wants 6 bytes, also 4 should be enough */
		char *s;

		if (
			UNICODE_IS_SURROGATE(i) ||
			UNICODE_IS_BYTE_ORDER_MARK(i) ||
			UNICODE_IS_ILLEGAL(i)
		) {
			continue;
		}

		size = g_unichar_to_utf8(i, utf8_char);
		g_assert(size < sizeof utf8_char);
		utf8_char[size] = '\0';
		utf8_decompose_nfd(utf8_char, buf, N_ITEMS(buf));
#if 1  /* !defined(xxxUSE_ICU) */
		s = g_utf8_normalize(utf8_char, -1, G_NORMALIZE_NFD);
#else
		{
			size_t len, maxlen;
			UChar *qtmp1, *qtmp2;

			maxlen = 1024;
			qtmp1 = (UChar *) g_malloc(maxlen * sizeof(UChar));
			qtmp2 = (UChar *) g_malloc(maxlen * sizeof(UChar));
			len = utf8_to_icu_conv(utf8_char, strlen(utf8_char), qtmp2, maxlen);
			g_assert(i == 0 || len != 0);
			len = unicode_NFKD(qtmp2, len, qtmp1, maxlen);
			g_assert(i == 0 || len != 0);
			s = g_malloc0((len * 6) + 1);
			len = icu_to_utf8_conv(qtmp2, len, s, len * 6);
			g_assert(i == 0 || len != 0);
			s[len] = '\0';
			G_FREE_NULL(qtmp2);
			G_FREE_NULL(qtmp1);
		}
#endif

		if (0 != strcmp(s, buf)) {
			const char *p;
			uint retlen;

			g_debug("\n0x%04X\nbuf=\"%s\"\ns=\"%s\"", i, buf, s);
			for (p = buf; '\0' != *p; p += retlen) {
				uint32 uc;

				uc = utf8_decode_char_fast(p, &retlen);
				if (!uc)
					break;
				g_debug("buf: U+%04X", uc);
			}
			for (p = s; '\0' != *p; p += retlen) {
				uint32 uc;

				uc = utf8_decode_char_fast(p, &retlen);
				if (!uc)
					break;
				g_debug("s: U+%04X", uc);
			}

#if GLIB_CHECK_VERSION(2, 4, 0) /* Glib >= 2.4.0 */
			/*
			 * The normalized strings should be identical. However, older
			 * versions of GLib do not normalize some characters properly.
			 */
			G_BREAKPOINT();
#endif /* GLib >= 2.4.0 */

		}
		G_FREE_NULL(s);
	}

	g_debug("random value: %u", (uint) random_value(~0));

	/* Check random Unicode strings */
	for (i = 0; i < 10000000; i++) {
		char buf[256 * 7];
		uint32 test[32], out[256];
		char *s, *t;
		size_t j, utf8_len, utf32_len, m, n;

		/* Check random strings */
		utf32_len = random_value(N_ITEMS(test) - 2) + 1;
		g_assert(utf32_len < N_ITEMS(test));
		for (j = 0; j < utf32_len; j++) {
			uint32 uc;

			do {
				uc = random_value(0x10FFFF);
				if (
						UNICODE_IS_SURROGATE(uc) ||
						UNICODE_IS_BYTE_ORDER_MARK(uc) ||
						UNICODE_IS_ILLEGAL(uc)
				   ) {
					uc = 0;
				}
			} while (!uc);
			test[j] = uc;
		}
		test[j] = 0;

#if 0
		/* This test case checks that the canonical sorting works i.e.,
		 * 0x0ACD must appear before all 0x05AF. */
		j = 0;
		test[j++] = 0x00B3;
		test[j++] = 0x05AF;
		test[j++] = 0x05AF;
		test[j++] = 0x05AF;
		test[j++] = 0x0ACD;
		test[j] = 0;
		utf32_len = j;

		g_assert(!utf32_canonical_sorted(test));
#endif

#if 0
		/* This test case checks that the canonical sorting uses a
		 * stable sort algorithm i.e., preserves the relative order
		 * of equal elements.  */
		j = 0;
		test[j++] = 0x0065;
		test[j++] = 0x0301;
		test[j++] = 0x01D165;
		test[j++] = 0x0302;
		test[j++] = 0x0302;
		test[j++] = 0x0304;
		test[j++] = 0x01D166;
		test[j++] = 0x01D165;
		test[j++] = 0x0302;
		test[j++] = 0x0300;
		test[j++] = 0x0305;
		test[j++] = 0x01D166;
		test[j] = 0;
		utf32_len = j;

		g_assert(!utf32_canonical_sorted(test));
#endif

#if 0
		j = 0;
		test[j++] = 0x32b;
		test[j++] = 0x93c;
		test[j++] = 0x22f0;
		test[j++] = 0xcb90;
		test[j] = 0;
		utf32_len = j;
#endif

#if 1
		j = 0;
		test[j++] = 0x239f;
		test[j++] = 0xcd5c;
		test[j++] = 0x11a7;
		test[j++] = 0x6d4c;
		test[j] = 0;
		utf32_len = j;
#endif


		utf8_len = utf32_to_utf8(test, buf, N_ITEMS(buf));
		g_assert(utf8_len < sizeof buf);
		g_assert(utf32_len <= utf8_len);

		n = utf8_is_valid_string(buf);
		g_assert(utf8_len >= n);
		g_assert(utf32_len == n);
		g_assert(utf8_is_valid_data(buf, utf8_len));
		g_assert(n == utf8_data_char_count(buf, utf8_len));

		n = utf8_to_utf32(buf, out, N_ITEMS(out));
		g_assert(n == utf32_len);
		g_assert(0 == memcmp(test, out, n * sizeof test[0]));

		n = utf8_decompose_nfkd(buf, NULL, 0) + 1;
		t = g_malloc(n);
		m = utf8_decompose_nfkd(buf, t, n);
		g_assert(m == n - 1);
		g_assert(utf8_canonical_sorted(t));

#if 1  /* !defined(xxxUSE_ICU) */
		s = g_utf8_normalize(buf, -1, G_NORMALIZE_NFKD);
#else
		{
			size_t len, maxlen;
			UChar *qtmp1, *qtmp2;

			maxlen = strlen(buf) * 6 + 1;
			qtmp1 = (UChar *) g_malloc(maxlen * sizeof(UChar));
			qtmp2 = (UChar *) g_malloc(maxlen * sizeof(UChar));
			len = utf8_to_icu_conv(buf, strlen(buf), qtmp1, maxlen);
			len = unicode_NFKD(qtmp1, len, qtmp2, maxlen);
			s = g_malloc0((len * 6) + 1);
			len = icu_to_utf8_conv(qtmp2, len, s, len * 6);
			s[len] = '\0';
			G_FREE_NULL(qtmp2);
			G_FREE_NULL(qtmp1);
		}
#endif

		if (0 != strcmp(s, t)) {
			const char *x, *y;
			uint32 *zx, *zy, uc1, uc2;
			uint retlen;

			/* Convert to UTF-32 so that the characters can be easily
			 * checked from a debugger */
			zx = g_malloc0(1024 * sizeof *zx);
			utf8_to_utf32(s, zx, 1024);
			zy = g_malloc0(1024 * sizeof *zy);
			utf8_to_utf32(t, zy, 1024);

			g_debug("s=\"%s\"\nt=\"%s\"", s, t);

			for (x = s, y = t; *x != '\0'; x++, y++)
				if (*x != *y)
					break;

			uc1 = utf8_decode_char_fast(x, &retlen);
			uc2 = utf8_decode_char(x, strlen(x), &retlen, TRUE);
			g_debug("x=\"%s\"\ny=\"%s\"\n, *x=%x, *y=%x", x, y, uc1, uc2);

#if GLIB_CHECK_VERSION(2, 4, 0) /* Glib >= 2.4.0 */
			/*
			 * The normalized strings should be identical. However, older
			 * versions of GLib do not normalize some characters properly.
			 */
			G_BREAKPOINT();
#endif /* GLib >= 2.4.0 */

			G_FREE_NULL(zx);
			G_FREE_NULL(zy);

		}
		G_FREE_NULL(s);
		G_FREE_NULL(t);
	}
#endif /* USE_GLIB2 */
}
#endif /* 0 */


#define REGRESSION(func) \
G_STMT_START { \
	g_debug("REGRESSION regression_%s()...", #func); \
	CAT2(regression_,func)(); \
} G_STMT_END

void G_COLD
utf8_regression_checks(void)
{
	/* unicode_compose_init() must be called before this */
	g_assert(unicode_compose_init_passed);

#if defined(TEST_NORMALIZATION_TEST_TXT)
	REGRESSION(normalization_test_txt);
#endif /* TEST_NORMALIZATION_TEST_TXT */

	REGRESSION(normalization_character_identity);
	REGRESSION(normalization_issue);
	REGRESSION(utf8_strlower);
	REGRESSION(bug_1211413);
	REGRESSION(iconv_utf8_to_utf8);
	REGRESSION(utf8_bijection);
	REGRESSION(utf8_unknown_conversion);

#if defined(TEST_UTF8_DECODER)
	REGRESSION(utf8_decoder);
#endif /* TEST_UTF8_DECODER */

#if 0 /* GLib 2.x implements an older version of Unicode */
	REGRESSION(utf8_vs_glib);
#endif

}

#if 0 /* For testing mingw_open() with Unicode support */
#undef open
int
my_open(const char *pathname, int flags, ...)
{
	int res;
	mode_t mode = 0;

	if (flags & O_CREAT) {
        va_list  args;

        va_start(args, flags);
        mode = (mode_t) va_arg(args, int);
        va_end(args);
    }

	if (utf8_is_valid_string(pathname)) {
		uint16 *pathname_utf16;
		char *pathname_utf8;

		pathname_utf16 = utf8_to_utf16_string(pathname);
		pathname_utf8 = utf16_to_utf8_string(pathname_utf16);
		g_assert(0 == strcmp(pathname, pathname_utf8));
		g_debug("pathname=\"%s\"", pathname_utf8);
		res = open(pathname_utf8, flags, mode);
		HFREE_NULL(pathname_utf8);
		HFREE_NULL(pathname_utf16);
	} else {
		res = open(pathname, flags, mode);
	}
	return res;
}
#endif	/* 0 */

/* vi: set ts=4 sw=4 cindent: */
