/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
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
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _utf8_h_
#define _utf8_h_

#include "common.h"

typedef enum {
	UNI_NORM_NFC = 0,
	UNI_NORM_NFKC,
	UNI_NORM_NFD,
	UNI_NORM_NFKD,

	NUM_UNI_NORM
} uni_norm_t;

/*
 * Gtk+ renderers want UTF-8 NFC
 */
#define UNI_NORM_GUI UNI_NORM_NFC

/*
 * NFC is more dense than NFD, thus it's the normalization of choice when
 * passing text over the wire.
 */
#define UNI_NORM_NETWORK UNI_NORM_NFC

#if defined(__APPLE__) && defined(__MACH__) /* Darwin */
/* Mac OS X (Darwin) wants filenames always in UTF-8 NFD */
#define UNI_NORM_FILESYSTEM UNI_NORM_NFD
#else /* !Darwin */
/* Unix systems usually use NFC for UTF-8 filenames */
#define UNI_NORM_FILESYSTEM UNI_NORM_NFC
#endif /* Darwin */

void locale_init(void);
void locale_close(void);
const gchar *locale_get_charset(void);
const gchar *locale_get_language(void);
guint utf8_char_len(const gchar *s);
gboolean is_ascii_string(const gchar *str);
gboolean utf8_is_valid_string(const gchar *s);
gboolean utf8_is_valid_data(const gchar *s, size_t n);
size_t utf8_char_count(const gchar *s);
size_t utf8_data_char_count(const gchar *src, size_t len);
size_t utf8_strlcpy(gchar *dst, const gchar *src, size_t dst_size);
size_t utf8_strcpy_max(gchar *dst, size_t dst_size,
			const gchar *src, size_t max_chars);
guint32 utf8_decode_char_fast(const gchar *s, guint *retlen)
	NON_NULL_PARAM((1,2));
gint utf8_to_iso8859(gchar *s, gint len, gboolean space);
size_t utf8_strlower(gchar *dst, const gchar *src, size_t size);
gchar *utf8_strlower_copy(const gchar *src);
size_t utf8_strupper(gchar *dst, const gchar *src, size_t size);
gchar *utf8_strupper_copy(const gchar *src);
gchar *utf8_canonize(const gchar *src);
gchar *utf8_normalize(const gchar *src, uni_norm_t norm);
gboolean utf8_is_decomposed(const gchar *src, gboolean nfkd);

guint NON_NULL_PARAM((2)) utf8_encode_char(guint32 uc, gchar *buf, size_t size);
size_t utf32_to_utf8(const guint32 *in, gchar *out, size_t size);
guint32 utf32_lowercase(guint32 uc);
gboolean utf32_canonical_sorted(const guint32 *src);
gboolean utf32_is_decomposed(const guint32 *src, gboolean nfkd);
size_t utf32_decompose_nfd(const guint32 *in, guint32 *out, size_t size);
size_t utf32_decompose_nfkd(const guint32 *in, guint32 *out, size_t size);
size_t utf32_strlower(guint32 *dst, const guint32 *src, size_t size);
size_t utf32_strupper(guint32 *dst, const guint32 *src, size_t size);

/**
 * This is a highly specialized function (read: don't use it if you don't
 * understand what it does and how it's used) to be used with
 * utf8_decode_char().
 * It's purpose is to determine the maximum possible length in bytes of
 * current UTF-8 character that ``s'' points to.
 *
 * @param s a UTF-8 encoded string.
 * @param len number of bytes pending to be decoded.
 *
 * @returns the maximum length in bytes of the current UTF-8 character.
 */
static inline size_t
utf8_decode_lookahead(const gchar *s, size_t len)
{
	while (len < 6 && s[len] != '\0')
		len++;
	return len;
}

/**
 * Encodes a single UTF-32 character as UTF-16 and return the result
 * compacted into a 32-bit integer.
 * See also RFC 2781.
 *
 * @param uc the unicode character to encode.
 * @returns (guint32) -1 if the unicode character is invalid. Otherwise the
 *         	UTF-16 encoded character is returned in a compact form:
 *			The lower 16 bits are the first UTF-16 character, the
 *			upper 16 bits are the second one. If the upper bits are
 *			all zero, the unicode character fit into 16 bits.
 */
static inline guint32
utf16_encode_char_compact(guint32 uc)
{
	if (uc <= 0xFFFF) {
		return uc;
	} else if (uc <= 0x10FFFF) {
		guint16 w1, w2;

		uc -= 0x10000;
		w1 = (uc >> 10) | 0xd800;
		w2 = (uc & 0x3ff) | 0xdc00;
		return (w2 << 16) | w1;
	}
	return (guint32) -1;
}

static inline gboolean
utf8_byte_is_allowed(guchar c)
{
	switch (c) {
	case 0xC0:
	case 0xC1:
	case 0xF5:
	case 0xF6:
	case 0xF7:
	case 0xF8:
	case 0xFA:
	case 0xFB:
	case 0xFC:
	case 0xFD:
	case 0xFE:
	case 0xFF:
		return FALSE;
	}
	return TRUE;
}

/**
 * Checks whether the character is a non-character which is not the
 * same as an unassigned character.
 *
 * @param uc an UTF-32 character
 * @return TRUE if the the character is a non-character, FALSE otherwise.
 */
static inline gboolean
utf32_is_non_character(guint32 uc)
{
	return 0xfffeU == (uc & 0xfffeU) || (uc >= 0xfdd0U && uc <= 0xfdefU);
}

static inline gboolean 
utf32_is_surrogate(guint32 cp)
{
  return cp >= 0xd800 && cp < 0xe000;
}

static inline gboolean
utf32_is_valid(guint32 cp)
{
  return cp < 0x10ffffU && !utf32_is_non_character(cp);
}

static inline unsigned
utf8_encoded_len(guint32 cp)
{
  if (cp < 0x80U) {
    return 1;
  } else if (cp < 0x800U) {
    return 2;
  } else if (!utf32_is_valid(cp) || utf32_is_surrogate(cp)) {
    return 0;
  } else if (cp < 0x10000U) {
    return 3;
  } else {
    return 4;
  }
}

static inline unsigned
utf8_first_byte_length_hint(unsigned char ch)
{
  switch (ch & ~0x0fU) {
  case 0x00:
  case 0x10:
  case 0x20:
  case 0x30:
  case 0x40:
  case 0x50:
  case 0x60:
  case 0x70: return 1;
  case 0xc0: return ch >= 0xc2 ? 2 : 0;
  case 0xd0: return 2;
  case 0xe0: return 3;
  case 0xf0: return ch <= 0xf4 ? 4 : 0;
  default:   return 0;
  }
}

static inline gboolean
utf8_first_byte_valid(unsigned char ch)
{
  return 0 != utf8_first_byte_length_hint(ch);
}

static inline gboolean
utf8_first_bytes_valid(unsigned char ch1, unsigned char ch2)
{
  if (ch1 < 0x80) {
    return TRUE;
  } else if (0x80 == (ch2 & 0xc0)) {
    /* 0x80..0xbf */
    switch (ch1) {
    case 0xe0: return ch2 >= 0xa0;
    case 0xed: return ch2 <= 0x9f;
    case 0xf0: return ch2 >= 0x90;
    case 0xf4: return ch2 <= 0x8f;
    }
    return TRUE;
  }
  return FALSE;
}

/**
 * @return (guint32)-1 on failure. On success the decoded Unicode codepoint
 *         is returned.
 */
static inline guint32
utf8_decode(const char *src, size_t size)
{
  guint32 cp;
  unsigned n;

  if (0 == size)
    goto failure;

  cp = (unsigned char) *src;
  n = utf8_first_byte_length_hint(cp);
  if (1 != n) {
    unsigned char x;

    if (0 == n || n > size)
      goto failure;
    
    x = *++src;
    if (!utf8_first_bytes_valid(cp, x))
      goto failure;

    n--;
    cp &= 0x3f >> n;

    for (;;) {
      cp = (cp << 6) | (x & 0x3f);
      if (--n == 0)
        break;
      x = *++src;
      if (0x80 != (x & 0xc0))
        goto failure;
    }
    if (utf32_is_non_character(cp))
      goto failure;
  }
  return cp;

failure:
  return (guint32) -1;
}

static inline unsigned
utf8_encode(guint32 cp, char *buf)
{
  unsigned n = utf8_encoded_len(cp);

  if (n > 0) {
    static const unsigned char first_byte[] = {
      0xff, 0x00, 0xc0, 0xe0, 0xf0
    };
    unsigned i = n;

    while (--i > 0) {
      buf[i] = (cp & 0x3f) | 0x80;
      cp >>= 6;
    }
    buf[0] = cp | first_byte[n];
  }
  return n;
}

/**
 * Lazy converters either return a pointer to a static buffer or manage
 * the allocated memory themselves. They may also return the original
 * pointer. Copy the result before calling them again unless you don't
 * need the previous result anymore.
 */
const gchar *lazy_iso8859_1_to_utf8(const gchar *src);

const gchar *lazy_ui_string_to_utf8(const gchar *src);
const gchar *lazy_utf8_to_ui_string(const gchar *src);

const gchar *lazy_utf8_to_locale(const gchar *src);
const gchar *lazy_locale_to_utf8(const gchar *src);

const gchar *lazy_locale_to_ui_string(const gchar *src);
const gchar *lazy_locale_to_ui_string2(const gchar *src);

const gchar *lazy_filename_to_ui_string(const gchar *src);

const gchar *lazy_filename_to_utf8_normalized(const gchar *str, uni_norm_t);
const gchar *lazy_locale_to_utf8_normalized(const gchar *src, uni_norm_t);
const gchar *lazy_unknown_to_utf8_normalized(const gchar *src, uni_norm_t,
				const gchar **charset_ptr);

const gchar *lazy_unknown_to_ui_string(const gchar *src);

gchar *iso8859_1_to_utf8(const gchar *str);
gchar *iso8859_1_to_utf8_normalized(const gchar *str, uni_norm_t norm);

gchar *unknown_to_ui_string(const gchar *src);
gchar *utf8_to_ui_string(const gchar *src);
gchar *ui_string_to_utf8(const gchar *src);

gchar *utf8_to_locale(const gchar *s);
gchar *locale_to_utf8(const gchar *str);
gchar *locale_to_utf8_normalized(const gchar *str, uni_norm_t norm);

gchar *utf8_to_filename(const gchar *s);
gchar *filename_to_utf8_normalized(const gchar *str, uni_norm_t norm);

gchar *unknown_to_utf8(const gchar *str, const gchar **charset_ptr);
gchar *unknown_to_utf8_normalized(const gchar *src, uni_norm_t norm,
			const gchar **charset_ptr);

size_t ascii_enforce(gchar *dst, size_t size, const gchar *src);
size_t utf8_enforce(gchar *dst, size_t size, const gchar *src);

gboolean icu_enabled(void);
gboolean locale_is_latin(void);
gboolean locale_is_utf8(void);

gboolean utf8_can_latinize(const gchar *src);
size_t utf8_latinize(gchar *dst, size_t dst_size, const gchar *src);

gint utf16_encode_char(guint32 uc, guint16 *dst);

#define UNICODE_CANONIZE(x) utf8_canonize(x)

#endif	/* _utf8_h_ */

/* vi: set sw=4 ts=4 cindent: */
