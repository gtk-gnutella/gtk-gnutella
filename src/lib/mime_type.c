/*
 * Copyright (c) 2008, Christian Biere
 * Copyright (c) 2008, Raphael Manfredi
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
 * Primitive MIME type handling.
 *
 * @author Christian Biere
 * @author Raphael Manfredi
 * @date 2008
 */

#include "common.h"

#include "ascii.h"
#include "mime_type.h"
#include "misc.h"

#include "override.h"		/* Must be the last header included */

static const struct {
	const char *extension;
	enum mime_type type;
} mime_type_map[] = {
	/* NOTE: Keep this sorted! */
	{ "7z",			MIME_TYPE_APPLICATION_7Z },
	{ "aac",		MIME_TYPE_AUDIO_MP4 },
	{ "ace",		MIME_TYPE_APPLICATION_ACE },
	{ "ai",			MIME_TYPE_APPLICATION_POSTSCRIPT },
	{ "apk",		MIME_TYPE_APPLICATION_ANDROID_PACKAGE },
	{ "asc",		MIME_TYPE_TEXT_PLAIN },
	{ "asf",		MIME_TYPE_VIDEO_MS_ASF },
	{ "ass",		MIME_TYPE_TEXT_PLAIN },
	{ "asx",		MIME_TYPE_VIDEO_MS_ASF },
	{ "au",			MIME_TYPE_AUDIO_BASIC },
	{ "avi",		MIME_TYPE_VIDEO_MSVIDEO },
	{ "bat",		MIME_TYPE_APPLICATION_DOSEXEC },
	{ "bittorrent",	MIME_TYPE_APPLICATION_BITTORRENT },
	{ "bmp",		MIME_TYPE_IMAGE_BMP },
	{ "bz2",		MIME_TYPE_APPLICATION_BZIP2 },
	{ "c",			MIME_TYPE_TEXT_C },
	{ "c++",		MIME_TYPE_TEXT_CPP },
	{ "cbr",		MIME_TYPE_APPLICATION_RAR },
	{ "cbt",		MIME_TYPE_APPLICATION_TAR },
	{ "cbz",		MIME_TYPE_APPLICATION_ZIP },
	{ "cc",			MIME_TYPE_TEXT_CPP },
	{ "chm",		MIME_TYPE_APPLICATION_COMPILED_HTML_HELP },
	{ "class",		MIME_TYPE_APPLICATION_JAVA_VM },
	{ "cls",		MIME_TYPE_APPLICATION_TEX },
	{ "com",		MIME_TYPE_APPLICATION_DOSEXEC },
	{ "cpp",		MIME_TYPE_TEXT_CPP },
	{ "css",		MIME_TYPE_TEXT_CSS },
	{ "csv",		MIME_TYPE_TEXT_CSV },
	{ "cxx",		MIME_TYPE_TEXT_CPP },
	{ "deb",		MIME_TYPE_APPLICATION_DEB },
	{ "diff",		MIME_TYPE_TEXT_DIFF },
	{ "dll",		MIME_TYPE_APPLICATION_DOSEXEC },
	{ "dmg",		MIME_TYPE_APPLICATION_DMG },
	{ "doc",		MIME_TYPE_APPLICATION_MSWORD },
	{ "dot",		MIME_TYPE_APPLICATION_MSWORD },
	{ "eml",		MIME_TYPE_MESSAGE_RFC822 },
	{ "eps",		MIME_TYPE_APPLICATION_POSTSCRIPT },
	{ "epub",		MIME_TYPE_APPLICATION_EPUB },
	{ "exe",		MIME_TYPE_APPLICATION_DOSEXEC },
	{ "flac",		MIME_TYPE_AUDIO_FLAC },
	{ "flv",		MIME_TYPE_VIDEO_FLV },
	{ "gb",			MIME_TYPE_APPLICATION_GAMEBOY_ROM },
	{ "gif",		MIME_TYPE_IMAGE_GIF },
	{ "gz",			MIME_TYPE_APPLICATION_GZIP },
	{ "h",			MIME_TYPE_TEXT_CHDR },
	{ "h++",		MIME_TYPE_TEXT_CPPHDR },
	{ "hh",			MIME_TYPE_TEXT_CPPHDR },
	{ "hpp",		MIME_TYPE_TEXT_CPPHDR },
	{ "htm",		MIME_TYPE_TEXT_HTML },
	{ "html",		MIME_TYPE_TEXT_HTML },
	{ "hxx",		MIME_TYPE_TEXT_CPPHDR },
	{ "ics",		MIME_TYPE_TEXT_CALENDAR },
	{ "icz",		MIME_TYPE_TEXT_CALENDAR },
	{ "ipa",		MIME_TYPE_APPLICATION_IPHONE_APP },
	{ "iso",		MIME_TYPE_APPLICATION_ISO9660 },
	{ "jar",		MIME_TYPE_APPLICATION_JAR },
	{ "java",		MIME_TYPE_TEXT_JAVA },
	{ "jpeg",		MIME_TYPE_IMAGE_JPEG },
	{ "jpg",		MIME_TYPE_IMAGE_JPEG },
	{ "js",			MIME_TYPE_APPLICATION_JAVASCRIPT },
	{ "kar",		MIME_TYPE_AUDIO_MIDI },
	{ "latex",		MIME_TYPE_TEXT_LATEX },
	{ "lha",		MIME_TYPE_APPLICATION_LZH },
	{ "lhz",		MIME_TYPE_APPLICATION_LZH },
	{ "lit",		MIME_TYPE_APPLICATION_MS_READER },
	{ "lnk",		MIME_TYPE_APPLICATION_MS_SHORTCUT },
	{ "lrf",		MIME_TYPE_APPLICATION_BROADBAND_EBOOK },
	{ "ltx",		MIME_TYPE_TEXT_LATEX },
	{ "ly",			MIME_TYPE_TEXT_LILYPOND },
	{ "lyx",		MIME_TYPE_APPLICATION_LYX },
	{ "m2a",		MIME_TYPE_AUDIO_MPEG },
	{ "m3u",		MIME_TYPE_AUDIO_MPEGURL },
	{ "m4a",		MIME_TYPE_AUDIO_MP4 },
	{ "m4v",		MIME_TYPE_VIDEO_MP4 },
	{ "man",		MIME_TYPE_APPLICATION_TROFF_MAN },
	{ "me",			MIME_TYPE_APPLICATION_TROFF_ME },
	{ "mid",		MIME_TYPE_AUDIO_MIDI },
	{ "midi",		MIME_TYPE_AUDIO_MIDI },
	{ "mka",		MIME_TYPE_AUDIO_MATROSKA },
	{ "mkv",		MIME_TYPE_VIDEO_MATROSKA },
	{ "mobi",		MIME_TYPE_APPLICATION_MOBIPOCKET_EBOOK },
	{ "mov",		MIME_TYPE_VIDEO_QUICKTIME },
	{ "mp2",		MIME_TYPE_AUDIO_MPEG },
	{ "mp3",		MIME_TYPE_AUDIO_MPEG },
	{ "mp4",		MIME_TYPE_VIDEO_MP4 },
	{ "mpa",		MIME_TYPE_AUDIO_MPEG },
	{ "mpeg",		MIME_TYPE_VIDEO_MPEG },
	{ "mpeg2",		MIME_TYPE_VIDEO_MPEG },
	{ "mpg",		MIME_TYPE_VIDEO_MPEG },
	{ "ms",			MIME_TYPE_APPLICATION_TROFF_MS },
	{ "n64",		MIME_TYPE_APPLICATION_N64_ROM },
	{ "nes",		MIME_TYPE_APPLICATION_NES_ROM },
	{ "nfo",		MIME_TYPE_TEXT_PLAIN },
	{ "o",			MIME_TYPE_APPLICATION_OBJECT },
	{ "oga",		MIME_TYPE_AUDIO_OGG },
	{ "ogg",		MIME_TYPE_APPLICATION_OGG },
	{ "ogm",		MIME_TYPE_VIDEO_OGM },
	{ "ogv",		MIME_TYPE_VIDEO_OGG },
	{ "opf",		MIME_TYPE_APPLICATION_OPEN_PACKAGING_FORMAT },
	{ "opus",		MIME_TYPE_AUDIO_OGG },
	{ "patch",		MIME_TYPE_TEXT_DIFF },
	{ "pdf",		MIME_TYPE_APPLICATION_PDF },
	{ "pif",		MIME_TYPE_APPLICATION_DOSEXEC },
	{ "pl",			MIME_TYPE_TEXT_PERL },
	{ "pls",		MIME_TYPE_AUDIO_PLAYLIST },
	{ "pm",			MIME_TYPE_TEXT_PERL },
	{ "png",		MIME_TYPE_IMAGE_PNG },
	{ "pot",		MIME_TYPE_TEXT_PLAIN },
	{ "pps",		MIME_TYPE_APPLICATION_POWERPOINT },
	{ "ppt",		MIME_TYPE_APPLICATION_POWERPOINT },
	{ "ps",			MIME_TYPE_APPLICATION_POSTSCRIPT },
	{ "psd",		MIME_TYPE_IMAGE_PSD },
	{ "py",			MIME_TYPE_TEXT_PYTHON },
	{ "qt",			MIME_TYPE_VIDEO_QUICKTIME },
	{ "ra",			MIME_TYPE_AUDIO_REALAUDIO },
	{ "rar",		MIME_TYPE_APPLICATION_RAR },
	{ "rdf",		MIME_TYPE_APPLICATION_RDF },
	{ "rmi",		MIME_TYPE_AUDIO_MIDI },
	{ "roff",		MIME_TYPE_APPLICATION_TROFF },
	{ "rss",		MIME_TYPE_APPLICATION_RSS },
	{ "rtf",		MIME_TYPE_TEXT_RTF },
	{ "scr",		MIME_TYPE_APPLICATION_DOSEXEC },
	{ "ser",		MIME_TYPE_APPLICATION_JAVA_SER },
	{ "sfv",		MIME_TYPE_TEXT_PLAIN },
	{ "sh",			MIME_TYPE_APPLICATION_SH },
	{ "shar",		MIME_TYPE_APPLICATION_SHAR },
	{ "shtml",		MIME_TYPE_TEXT_HTML },
	{ "sit",		MIME_TYPE_APPLICATION_SIT },
	{ "sitx",		MIME_TYPE_APPLICATION_SIT },
	{ "smc",		MIME_TYPE_APPLICATION_SNES_ROM },
	{ "smd",		MIME_TYPE_APPLICATION_GENESIS_ROM },
	{ "snd",		MIME_TYPE_AUDIO_BASIC },
	{ "spx",		MIME_TYPE_AUDIO_SPEEX },
	{ "srt",		MIME_TYPE_TEXT_PLAIN },
	{ "ssa",		MIME_TYPE_TEXT_PLAIN },
	{ "sty",		MIME_TYPE_APPLICATION_TEX },
	{ "swf",		MIME_TYPE_APPLICATION_SHOCKWAVE_FLASH },
	{ "t",			MIME_TYPE_APPLICATION_TROFF },
	{ "tar",		MIME_TYPE_APPLICATION_TAR },
	{ "tbz2",		MIME_TYPE_APPLICATION_BZIP2 },
	{ "tex",		MIME_TYPE_APPLICATION_TEX },
	{ "texi",		MIME_TYPE_APPLICATION_TEXINFO },
	{ "texinfo",	MIME_TYPE_APPLICATION_TEXINFO },
	{ "text",		MIME_TYPE_TEXT_PLAIN },
	{ "tga",		MIME_TYPE_IMAGE_TGA },
	{ "tgz",		MIME_TYPE_APPLICATION_GZIP },
	{ "tif",		MIME_TYPE_IMAGE_TIFF },
	{ "tiff",		MIME_TYPE_IMAGE_TIFF },
	{ "torrent",	MIME_TYPE_APPLICATION_BITTORRENT },
	{ "tr",			MIME_TYPE_APPLICATION_TROFF },
	{ "txt",		MIME_TYPE_TEXT_PLAIN },
	{ "wav",		MIME_TYPE_AUDIO_WAVE },
	{ "webm",		MIME_TYPE_VIDEO_WEBM },	/* Could also be audio-only! */
	{ "wma",		MIME_TYPE_AUDIO_MS_ASF },
	{ "wmv",		MIME_TYPE_VIDEO_MS_ASF },
	{ "xhtml",		MIME_TYPE_TEXT_XHTML },
	{ "xls",		MIME_TYPE_APPLICATION_EXCEL },
	{ "xml",		MIME_TYPE_TEXT_XML },
	{ "xpm",		MIME_TYPE_IMAGE_XPM },
	{ "z",			MIME_TYPE_APPLICATION_COMPRESS },
	{ "zip",		MIME_TYPE_APPLICATION_ZIP },
	{ "zoo",		MIME_TYPE_APPLICATION_ZOO },

	/* Above line intentionally left blank (for "!}sort" on vi) */
};

/**
 * Returns the MIME content type string.
 */
const char *
mime_type_to_string(enum mime_type type)
{
	static const char *names[] = {
#define MIME_TYPE(id, name) name,
#include "mime_types.h"
#undef MIME_TYPE
	};
	size_t i;
	
	STATIC_ASSERT(MIME_TYPE_NUM == G_N_ELEMENTS(names));
	i = (size_t) type < G_N_ELEMENTS(names)
			? type : MIME_TYPE_APPLICATION_OCTET_STREAM;
	return names[i];
}

/**
 * Computes the MIME type to use based on the supplied file extension.
 *
 * @param extension		the file name extension (e.g. "zip" or "html")
 *
 * @return the dedicated MIME type, or MIME_TYPE_APPLICATION_OCTET_STREAM when
 * the extension is not recognized.
 */
enum mime_type
mime_type_from_extension(const char *extension)
{
	if (extension) {
#define GET_KEY(i)	mime_type_map[(i)].extension
#define FOUND(i) 	return mime_type_map[(i)].type;

		BINARY_SEARCH(const char *, extension,
			G_N_ELEMENTS(mime_type_map),
			ascii_strcasecmp, GET_KEY, FOUND);

#undef FOUND
#undef GET_KEY
	}
	return MIME_TYPE_APPLICATION_OCTET_STREAM;
}

/**
 * Computes the MIME type to use based on the extension present in the
 * file name.
 *
 * The extension is whatever comes after the final "." in the name.
 *
 * @param filename		the file name
 *
 * @return the dedicated MIME type, or MIME_TYPE_APPLICATION_OCTET_STREAM when
 * the extension is not recognized.
 */
enum mime_type
mime_type_from_filename(const char *filename)
{
	const char *extension;
	
	g_return_val_if_fail(filename, MIME_TYPE_APPLICATION_OCTET_STREAM);
	extension = strrchr(filename, '.');
	return mime_type_from_extension(extension ? &extension[1] : NULL);
}

/**
 * Initialize the MIME table.
 */
void G_COLD
mime_type_init(void)
{
	size_t i;

	/*
	 * Ensure the MIME table is sorted.
	 */

	for (i = 0; i < G_N_ELEMENTS(mime_type_map); i++) {
		enum mime_type ret;

		ret = mime_type_from_extension(mime_type_map[i].extension);
		if (ret != mime_type_map[i].type) {
			g_error("mime_type_map[] is not sorted!");
		}
	}
}

/* vi: set ts=4 sw=4 cindent: */

