/*
 * $Id$
 *
 * Copyright (c) 2002-2003, Raphael Manfredi
 *
 * Unicode Transformation Format 8 bits.
 *
 * This code has been heavily inspired by utf8.c/utf8.h from Perl 5.6.1,
 * written by Larry Wall et al.
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

#include "common.h"

#ifdef ENABLE_NLS
#include <libintl.h>
#endif /* ENABLE_NLS */

#include <string.h>

#include "utf8.h"
#include "misc.h"

RCSID("$Id$");

#include "gnutella.h" /* dbg */

#if !defined(USE_GTK2) || defined(ENABLE_NLS)
#include <iconv.h>
#include <locale.h>

#ifdef I_LIBCHARSET
#include <libcharset.h>
#else
#include <langinfo.h>
#endif /* I_LIBCHARSET */

#endif /* !USE_GTK2 || ENABLE_NLS */
 
#ifndef USE_GTK2
#define GIConv iconv_t
#define g_iconv_open(t, f) iconv_open(t, f) 
#define g_iconv(c, i, n, o, m) iconv(c, i, n, o, m)

#endif /* !USE_GTK2 */

static GIConv cd_locale_to_utf8	= (GIConv) -1;
static GIConv cd_utf8_to_locale	= (GIConv) -1;
static GIConv cd_latin_to_utf8	= (GIConv) -1;

/*
 * How wide is an UTF-8 encoded char, depending on its first byte?
 */
static guint8 utf8len[256] = {
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,		/* 000-015: ASCII */
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,		/* 016-031: ASCII */
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,		/* 032-047: ASCII */
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,		/* 048-063: ASCII */
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,		/* 064-079: ASCII */
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,		/* 080-095: ASCII */
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,		/* 096-111: ASCII */
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,		/* 112-127: ASCII */
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,		/* 128-143: invalid! */
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,		/* 128-159: invalid! */
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,		/* 160-175: invalid! */
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,		/* 176-191: invalid! */
	2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,		/* 192-207 */
	2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,		/* 208-223 */
	3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,		/* 224-239 */
	4,4,4,4,4,4,4,4,5,5,5,5,6,6,			/* 240-253 */
	7,7										/* 254-255: special */
};

#define UTF8_SKIP(s)	utf8len[*((const guchar *) s)]

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

#define CHAR(x)					((guchar) (x))
#define UTF8_IS_ASCII(x)		(CHAR(x) < 0x80)
#define UTF8_IS_START(x)		(CHAR(x) >= 0xc0 && CHAR(x) <= 0xfd)
#define UTF8_IS_CONTINUATION(x)	(CHAR(x) >= 0x80 && CHAR(x) <= 0xbf)
#define UTF8_IS_CONTINUED(x)	(CHAR(x) & 0x80)

#define UTF8_CONT_MASK			(CHAR(0x3f))
#define UTF8_ACCU_SHIFT			6
#define UTF8_ACCUMULATE(o,n)	\
	(((o) << UTF8_ACCU_SHIFT) | (CHAR(n) & UTF8_CONT_MASK))

#define UNISKIP(v) (			\
	(v) <  0x80 		? 1 :	\
	(v) <  0x800 		? 2 :	\
	(v) <  0x10000 		? 3 :	\
	(v) <  0x200000		? 4 :	\
	(v) <  0x4000000	? 5 :	\
	(v) <  0x80000000	? 6 : 7)

#define UNI_SURROGATE_FIRST		0xd800
#define UNI_SURROGATE_LAST		0xdfff
#define UNI_REPLACEMENT			0xfffd
#define UNI_BYTE_ORDER_MARK		0xfffe
#define UNI_ILLEGAL				0xffff

#define UNICODE_IS_SURROGATE(x)	\
	((x) >= UNI_SURROGATE_FIRST && (x) <= UNI_SURROGATE_LAST)

#define UNICODE_IS_REPLACEMENT(x)		((x) == UNI_REPLACEMENT)
#define UNICODE_IS_BYTE_ORDER_MARK(x)	((x) == UNI_BYTE_ORDER_MARK)
#define UNICODE_IS_ILLEGAL(x)			((x) == UNI_ILLEGAL)

/*
 * utf8_is_valid_char
 *
 * Are the first bytes of string `s' forming a valid UTF-8 character?
 * Returns amount of bytes used to encode that character, or 0 if invalid.
 */
gint utf8_is_valid_char(const gchar *s)
{
	const guchar u = (guchar) *s;
	gint len;
	gint slen;
	guint32 v;
	guint32 ov;

	if (UTF8_IS_ASCII(u))
		return 1;

	if (!UTF8_IS_START(u))
		return 0;

	len = UTF8_SKIP(s);

	if (len < 2 || !UTF8_IS_CONTINUATION(s[1]))
		return 0;

	for (slen = len - 1, s++, ov = v = u; slen; slen--, s++, ov = v) {
		if (!UTF8_IS_CONTINUATION(*s))
			return 0;
		v = UTF8_ACCUMULATE(v, *s);
		if (v < ov)
			return 0;
	}

	if (UNISKIP(v) < len)
		return 0;

	return len;
}

/*
 * utf8_is_valid_string
 *
 * Returns amount of UTF-8 chars when first `len' bytes of the given string
 * `s' form valid a UTF-8 string, 0 meaning the string is not valid UTF-8.
 *
 * If `len' is 0, the length is computed with strlen().
 */
gint utf8_is_valid_string(const gchar *s, gint len)
{
	const gchar *x = s;
	const gchar *s_end;
	gint n = 0;

	if (!len)
		len = strlen(s);
	s_end = s + len;

	while (x < s_end) {
		gint clen = utf8_is_valid_char(x);
		if (clen == 0)
			return 0;
		x += clen;
		n++;
	}

	if (x != s_end)
		return 0;

	return n;
}

/*
 * utf8_decode_char
 *
 * Returns the character value of the first character in the string `s',
 * which is assumed to be in UTF-8 encoding and no longer than `len'.
 * `retlen' will be set to the length, in bytes, of that character.
 *
 * If `s' does not point to a well-formed UTF-8 character, the behaviour
 * is dependent on the value of `warn'.  When FALSE, it is assumed that
 * the caller will raise a warning, and this function will silently just
 * set `retlen' to -1 and return zero.
 */
guint32 utf8_decode_char(gchar *s, gint len, gint *retlen, gboolean warn)
{
	guint32 v = *s;
	guint32 ov = 0;
	gint clen = 1;
	gint expectlen = 0;
	gint warning = -1;
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
#define UTF8_WARN_FFFF				9

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
	} else if (expectlen > UNISKIP(v)) {
		warning = UTF8_WARN_LONG;
		goto malformed;
	} else if (UNICODE_IS_ILLEGAL(v)) {
		warning = UTF8_WARN_FFFF;
		goto malformed;
	}

	return v;

malformed:

	if (!warn) {
		if (retlen)
			*retlen = -1;
		return 0;
	}

	switch (warning) {
	case UTF8_WARN_EMPTY:
		gm_snprintf(msg, sizeof(msg), "empty string");
		break;
	case UTF8_WARN_CONTINUATION:
		gm_snprintf(msg, sizeof(msg),
			"unexpected continuation byte 0x%02lu", (gulong) v);
		break;
	case UTF8_WARN_NON_CONTINUATION:
		gm_snprintf(msg, sizeof(msg),
			"unexpected non-continuation byte 0x%02lu "
			"after start byte 0x%02ld", (gulong) s[1], (gulong) v);
		break;
	case UTF8_WARN_FE_FF:
		gm_snprintf(msg, sizeof(msg), "byte 0x%02lu", (gulong) v);
		break;
	case UTF8_WARN_SHORT:
		gm_snprintf(msg, sizeof(msg), "%d byte%s, need %d",
			len, len == 1 ? "" : "s", expectlen);
		break;
	case UTF8_WARN_OVERFLOW:
		gm_snprintf(msg, sizeof(msg), "overflow at 0x%02lu, byte 0x%02lu",
			(gulong) ov, (gulong) *s);
		break;
	case UTF8_WARN_SURROGATE:
		gm_snprintf(msg, sizeof(msg), "UTF-16 surrogate 0x04%lu", (gulong) v);
		break;
	case UTF8_WARN_BOM:
		gm_snprintf(msg, sizeof(msg), "byte order mark 0x%04lu", (gulong) v);
		break;
	case UTF8_WARN_LONG:
		gm_snprintf(msg, sizeof(msg), "%d byte%s, need %d",
			expectlen, expectlen == 1 ? "" : "s", UNISKIP(v));
		break;
	case UTF8_WARN_FFFF:
		gm_snprintf(msg, sizeof(msg), "character 0x%04lu", (gulong) v);
		break;
	default:
		gm_snprintf(msg, sizeof(msg), "unknown reason");
		break;
	}

	g_warning("malformed UTF-8 character: %s", msg);

	if (retlen)
		*retlen = expectlen ? expectlen : len;

	return 0;
}

/*
 * utf8_to_iso8859
 *
 * Convert UTF-8 string to ISO-8859-1 inplace.  If `space' is TRUE, all
 * characters outside the U+0000 .. U+00FF range are turned to space U+0020.
 * Otherwise, we stop at the first out-of-range character.
 *
 * If `len' is 0, the length of the string is computed with strlen().
 *
 * Returns length of decoded string.
 */
gint utf8_to_iso8859(gchar *s, gint len, gboolean space)
{
	gchar *x = s;
	gchar *xw = s;			/* Where we write back ISO-8859 chars */
	gchar *s_end;

	if (!len)
		len = strlen(s);
	s_end = s + len;

	while (x < s_end) {
		gint clen;
		guint32 v = utf8_decode_char(x, len, &clen, FALSE);

		if (clen == -1)
			break;

		g_assert(clen >= 1);

		if (v & 0xffffff00) {	/* Not an ISO-8859-1 character */
			if (!space)
				break;
			v = 0x20;
		}

		*xw++ = (guchar) v;
		x += clen;
		len -= clen;
	}

	*xw = '\0';

	return xw - s;
}


#if !defined(USE_GTK2) && !defined(I_LIBCHARSET)

/* List of known codesets. The first word of each string is the alias to be
 * returned. The words are seperated by whitespaces.
 */
static const char *codesets[] = {
 "ASCII ISO_646.IRV:1983 646 C US-ASCII la_LN.ASCII lt_LN.ASCII",
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

/*
 * locale_charset:
 *
 * Returns a string representing the current locale as an alias which is
 * understood by GNU iconv. The returned pointer points to a static buffer.
 */
const char *locale_charset(void)
{
	int i = 0;
	const char *cs;
	const char *start = codesets[0]; 
	const char *first_end = NULL;
	size_t cs_len;

	cs = nl_langinfo(CODESET);
	if (NULL == cs || '\0' == *cs)
		return NULL;

	cs_len = strlen(cs);

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
		if (len > 0 && 0 == g_ascii_strncasecmp(cs, start, cs_len)) {
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
#endif /* ENABLE_NLS && !I_LIBCHARSET */

static const gchar *charset = NULL;

const gchar *locale_get_charset(void)
{
	return charset;
}

static void textdomain_init(const char *charset)
{
#ifdef ENABLE_NLS
	bindtextdomain(PACKAGE, LOCALEDIR);

#ifdef HAS_BIND_TEXTDOMAIN_CODESET

	bind_textdomain_codeset(PACKAGE,
#ifdef USE_GTK2	
		"UTF-8"
#else
		charset
#endif /* USE_GTK2*/
	);

#endif /* HAS_BIND_TEXTDOMAIN_CODESET */

	textdomain(PACKAGE);
#endif /* NLS */
}

void locale_init(void)
{

#ifdef ENABLE_NLS
	setlocale(LC_ALL, "");
#endif /* NLS */

#ifdef USE_GTK2

	g_get_charset(&charset);

#else

#if defined(I_LANGINFO) || defined(I_LIBCHARSET)
	charset = locale_charset();
#endif /* I_LANGINFO || I_LIBCHARSET */

	if (charset == NULL) {
		charset = "ISO-8859-1";		/* Default locale codeset */
		g_warning("locale_init: Using default codeset %s as fallback.",
			charset);
	}

#endif /* USE_GTK2 */

	textdomain_init(charset);

	if ((GIConv)-1 == (cd_latin_to_utf8 = g_iconv_open("UTF-8", "ISO-8859-1")))
		g_warning("g_iconv_open(\"UTF-8\", \"ISO-8859-1\") failed.");
	if (strcmp("ISO-8859-1", charset) > 0) {
		if ((GIConv)-1 == (cd_locale_to_utf8 = g_iconv_open("UTF-8", charset)))
			g_warning("g_iconv_open(\"UTF-8\", \"%s\") failed.", charset);
	} else {
		cd_locale_to_utf8 = cd_latin_to_utf8;
	}
	if ((GIConv)-1 == (cd_utf8_to_locale = g_iconv_open(charset, "UTF-8")))
		g_warning("g_iconv_open(\"%s\", \"UTF-8\") failed.", charset);
}


static inline char *g_iconv_complete(GIConv cd,
	char *inbuf, size_t inbytes_left,
	char *outbuf, size_t outbytes_left)
{
	gchar *result = outbuf;

	if ((GIConv) -1 == cd)
		return NULL;

	if (outbytes_left > 0)
		outbuf[0] = '\0';

	while (inbytes_left > 0 && outbytes_left > 0) {
		size_t ret;

		ret = g_iconv(cd, &inbuf, &inbytes_left, &outbuf, &outbytes_left);
		if ((size_t) -1 == ret) {
			switch (errno) {
			case EILSEQ:
			case EINVAL:
				if (dbg > 1)
					g_warning("g_iconv_complete: g_iconv() failed soft: %s",
						g_strerror(errno));
				*outbuf = '_';
				outbuf++;
				outbytes_left--;
				inbuf++;
				inbytes_left--;
				break;
			default:
				if (dbg > 1)
					g_warning("g_iconv_complete(): g_iconv() failed hard: %s",
						g_strerror(errno));
				return NULL;
			}
		}
	}
	*outbuf = '\0';
	return result;
}

/*
 * locale_to_utf8
 *
 * If ``len'' is 0 the length will be calculated using strlen(), otherwise
 * only ``len'' characters will be converted.
 * If the string is already valid UTF-8 it will be returned "as-is".
 * The function might return a pointer to a STATIC buffer! If the output
 * string is longer than 4095 characters it will be truncated.
 * Non-convertible characters will be replaced by '_'. The returned string
 * WILL be NUL-terminated in any case.
 *
 * In case of an unrecoverable error, NULL is returned.
 *
 * ATTENTION:	Don't use this function for anything but *uncritical*
 *				strings	e.g., to view strings in the GUI. The conversion
 *				MAY be inappropriate!
 */
gchar *locale_to_utf8(gchar *str, size_t len)
{
	static gchar outbuf[4096 + 6]; /* an UTF-8 char is max. 6 bytes large */

	g_assert(NULL != str);

	if (0 == len)
		len = strlen(str);
	if (utf8_is_valid_string(str, len))
		return str;
	else
		return g_iconv_complete(cd_locale_to_utf8,
				str, len, outbuf, sizeof(outbuf) - 7);
}

gchar *utf8_to_locale(gchar *str, size_t len)
{
	static gchar outbuf[4096 + 6]; /* a multibyte char is max. 6 bytes large */

	g_assert(NULL != str);

	return g_iconv_complete(cd_utf8_to_locale,
				str, len != 0 ? len : strlen(str), outbuf, sizeof(outbuf) - 7);
}


gboolean is_ascii_string(const gchar *str)
{
	while (*str)
		if (*str++ & 0x80)
	        return FALSE;

    return TRUE;
}

gchar *iso_8859_1_to_utf8(gchar *fromstr)
{
	static gchar outbuf[4096 + 6]; /* a multibyte char is max. 6 bytes large */

	g_assert(NULL != fromstr);
 
	return g_iconv_complete(cd_latin_to_utf8,
				fromstr, strlen(fromstr), outbuf, sizeof(outbuf) - 7);
}

gchar *lazy_utf8_to_locale(gchar *str, size_t len)
{
	gchar *t = utf8_to_locale(str, len);
	return NULL != t ? t : "<Cannot convert to locale>";
}

gchar *lazy_locale_to_utf8(gchar *str, size_t len)
{
	gchar *t = locale_to_utf8(str, len);
	return NULL != t ? t : "<Cannot convert to UTF-8>";
}
