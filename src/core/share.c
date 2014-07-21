/*
 * Copyright (c) 2001-2005, 2013 Raphael Manfredi
 * Copyright (c) 2000 Daniel Walker (dwalker@cats.ucsc.edu)
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
 * Handle sharing of our own files and answers to remote queries.
 *
 * @author Daniel Walker (dwalker@cats.ucsc.edu)
 * @date 2000
 * @author Raphael Manfredi
 * @date 2001-2005, 2013
 */

#include "common.h"

#include "share.h"
#include "extensions.h"
#include "downloads.h"
#include "fileinfo.h"
#include "ggep_type.h"
#include "gmsg.h"
#include "gnet_stats.h"
#include "guid.h"
#include "hosts.h"
#include "huge.h"
#include "nodes.h"
#include "oob.h"
#include "oob_proxy.h"
#include "publisher.h"
#include "qhit.h"
#include "qrp.h"
#include "search.h"
#include "settings.h"
#include "spam.h"
#include "upload_stats.h"
#include "uploads.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"
#include "if/bridge/c2ui.h"

#include "lib/ascii.h"
#include "lib/atomic.h"
#include "lib/atoms.h"
#include "lib/barrier.h"
#include "lib/bg.h"
#include "lib/cq.h"
#include "lib/endian.h"
#include "lib/file.h"
#include "lib/getcpucount.h"
#include "lib/halloc.h"
#include "lib/hashing.h"
#include "lib/hikset.h"
#include "lib/hset.h"
#include "lib/htable.h"
#include "lib/listener.h"
#include "lib/mime_type.h"
#include "lib/pslist.h"
#include "lib/str.h"
#include "lib/stringify.h"
#include "lib/teq.h"
#include "lib/thread.h"
#include "lib/tm.h"
#include "lib/tsig.h"
#include "lib/utf8.h"
#include "lib/vsort.h"
#include "lib/walloc.h"
#include "lib/xmalloc.h"

#include "lib/override.h"		/* Must be the last header included */

#define SHARE_RECENT_THRESH		(2 * 7 * 24 * 60 * 60)	/* 2 weeks */

enum shared_file_magic {
	SHARED_FILE_MAGIC = 0x3702b437U
};

/**
 * A shared file description.
 *
 * These objects are ref-counted.
 *
 * Although they can be accessed from multiple threads, most accesses are
 * read-only and the application normally changes fields only from the main
 * thread.
 *
 * Therefore, it is not necessary to lock the objects before accessing them,
 * although the reference count field needs to be accessed through atomic
 * operations because it can be concurrently updated.
 *
 * During library rebuilding operations, which are done in a separate thread,
 * a new set of objects is created by the rebuild thread before being made
 * visible to the main thread, hence the rebuild thread doe not require locking
 * of the objects either.
 */
struct shared_file {
	enum shared_file_magic magic;

	struct dl_file_info *fi;	/**< PFSP-server: the holding fileinfo */
	const struct sha1 *sha1;	/**< SHA1 digest, binary form, atom */
	const struct tth *tth;		/**< TTH digest, binary form, atom */

	const char *file_path;		/**< The full path of the file (atom!) */
	const char *name_nfc;		/**< UTF-8 NFC version of filename (atom!) */
	const char *name_canonic;	/**< UTF-8 canonized ver. of filename (atom)! */
	const char *relative_path;	/**< UTF-8 NFC string (atom) */

	size_t name_nfc_len;		/**< strlen(name_nfc) */
	size_t name_canonic_len;	/**< strlen(name_canonic) */

	time_t mtime;				/**< Last modif. time, for SHA1 computation */
	time_t ctime;				/**< File creation time */

	filesize_t file_size;		/**< File size in Bytes */
	uint32 file_index;			/**< the files index within our local DB */
	uint32 sort_index;			/**< the index for sorted listings */

	enum mime_type mime_type;	/* MIME type of the file */

	int refcnt;					/**< Reference count */
	uint32 flags;				/**< See below for definition */
};

/**
 * Describes special files which are served by GTKG.
 */
struct special_file {
	const char *path;			/* URL path */
	const char *file;			/* File name to load from disk */
	enum mime_type type;		/* MIME type of the file */
	const char *what;			/* Description of the file for traces */
};

static const struct special_file specials[] = {
	{ "/favicon.ico",
			"favicon.png",	MIME_TYPE_IMAGE_PNG,	"Favorite web icon" },
	{ "/robots.txt",
			"robots.txt",	MIME_TYPE_TEXT_PLAIN,	"Robot exclusion" },
};

/**
 * Maps special names (e.g. "/favicon.ico") to the shared_file_t structure.
 */
static htable_t *special_names;

static hset_t *extensions;	/* Shared filename extensions */
static pslist_t *shared_dirs;
static cevent_t *share_qrp_rebuild_ev;

static hset_t *partial_files;	/* Contains partial files, thread-safe */

/*
 * These variables are recreated by each library scanning.
 *
 * During a rebuild of the library, their old values remain present so that
 * we can continue to serve files without interruption.  Only at the end of
 * the rebuilding process do we atomically update all of them with the new
 * values, freeing old content.
 *
 * To make sure we never access them without locking, they are groupped in
 * a structure and accessors are defined.
 */
static struct shared_library {
	uint64 files_scanned;	/* Amount of files shared in the library */
	uint64 bytes_scanned;
	pslist_t *shared_files;
	search_table_t *search_table;
	htable_t *file_basenames;
	search_table_t *partial_table;
	shared_file_t **file_table;			/* Sorted by mtime */
	shared_file_t **sorted_file_table;	/* Sorted by name */
} shared_libfile;
static spinlock_t shared_libfile_slk = SPINLOCK_INIT;

#define SHARED_LIBFILE_LOCK		spinlock(&shared_libfile_slk)
#define SHARED_LIBFILE_UNLOCK	spinunlock(&shared_libfile_slk)

#define assert_shared_libfile_locked()	\
	g_assert(spinlock_is_held(&shared_libfile_slk))

#define GENERATE_ACCESSOR(type, field)	\
static inline type field() {			\
	type result;						\
	SHARED_LIBFILE_LOCK;				\
	result = shared_libfile.field;		\
	SHARED_LIBFILE_UNLOCK;				\
	return result;						\
}

GENERATE_ACCESSOR(uint64, files_scanned)
GENERATE_ACCESSOR(uint64, bytes_scanned)

#undef GENERATE_ACCESSOR

/**
 * The recursive_scan_context is the context used by two distinct background
 * tasks, which cannot run at the same time:
 *
 * - the library rescan
 * - the rebuilding of the QRP tables
 *
 * The library rescan looks through all the shared directories to identify the
 * files that match the configured extensions and should therefore be included
 * in the shared list.  It terminates with the rebuilding of the QRP tables,
 * in the same task context.
 *
 * When running on a system with more than 1 CPU, the background task actually
 * runs in a dedicated thread, but the task does not need to know that.
 *
 * From a user standpoint, we want to be able to ask for library rescans or
 * rebuilding of the QRP tables, be able to cancel the task and restart a new
 * one, or wait for the previous task to complete and launch a new one.
 *
 * To properly cleanup memory when the task is cancelled, the background task
 * reclaims its allocated context in its "free context" callback at the end
 * of its processing (be it a regular end or the result of a cancellation).
 * Note that we're talking about the task cancellation here, not that of the
 * thread that runs it!
 *
 * Once the background task starts to be scheduled by the thread (which may not
 * be the main thread on multi-core systems), the context needs to be only
 * accessed by that thread, to avoid having to lock the context each time.
 *
 * The implementation works as follows: we create a "library" thread on systems
 * with more than 1 CPU and equip it with a thread event queue (TEQ), recording
 * the thread ID of that library thread.  If there is only 1 CPU, the thread ID
 * will be that of the main thread.
 *
 * We then "talk" to the library thread via inter-thread RPCs, using the TEQ.
 * These RPCs translate into direct function calls when the target thread ID is
 * that of the caller, so the caller does not know whether it talks to itself
 * or to another thread.
 *
 * Our convention is that from the "main" thread our interface to the "library"
 * thread are routines starting with the "share_lib_" prefix.  The corresponding
 * RPC targets, executed in the context of the "library" thread start with
 * "share_thread_lib_".
 */
static struct share_thread_vars {
	spinlock_t lock;					/* Lock to allow concurrent access */
	bgsched_t *sched;					/* Background task scheduler */
	struct bgtask *task;				/* Current task, NULL if none */
	bool qrp_rebuild;					/* Whether QRP rebuild is pending */
	bool exiting;						/* Whether thread should exit */
} share_thread_vars = {
	SPINLOCK_INIT,			/* lock */
	NULL,					/* sched */
	NULL,					/* task */
	FALSE,					/* qrp_rebuild */
	FALSE,					/* exiting */
};
static unsigned share_thread_id = THREAD_INVALID_ID;
static bool share_rebuilding;			/* Whether library is being rebuilt */

/**
 * This hash table maps a SHA1 hash (base-32 encoded) onto the corresponding
 * shared_file if we have one.
 */
static hikset_t *sha1_to_share;		/* Marked thread-safe */

#define A	SEARCH_AUDIO_TYPE
#define V	SEARCH_VIDEO_TYPE
#define D	SEARCH_DOC_TYPE
#define I	SEARCH_IMG_TYPE
#define U	(SEARCH_WIN_TYPE | SEARCH_UNIX_TYPE)

/**
 * This table encodes for each known MIME type the searchable media type bits
 * that are applicable for that type.
 *
 * A 0 (zero) entry means the corresponding MIME type will never match any
 * of the searchable bits.  This typically indicates a file containing
 * either application-specific data (e.g. an MP3 playlist), a programming
 * language (e.g. a C header file), or binary-specific data (e.g. a ROM
 * image).
 */
static struct {
	enum mime_type type;
	unsigned flags;
} media_type_map[] = {
	/* NOTE: this is mapped to a hash, but keep sorted for easier updates */
	{ MIME_TYPE_APPLICATION_7Z,						U },
	{ MIME_TYPE_APPLICATION_ACE,					U },
	{ MIME_TYPE_APPLICATION_ANDROID_PACKAGE,		U },
	{ MIME_TYPE_APPLICATION_BITTORRENT,				D },
	{ MIME_TYPE_APPLICATION_BROADBAND_EBOOK,		D },
	{ MIME_TYPE_APPLICATION_BZIP2,					U },
	{ MIME_TYPE_APPLICATION_COMPILED_HTML_HELP,		D },
	{ MIME_TYPE_APPLICATION_COMPRESS,				U },
	{ MIME_TYPE_APPLICATION_DEB,					U },
	{ MIME_TYPE_APPLICATION_DMG,					U },
	{ MIME_TYPE_APPLICATION_DOSEXEC,				U },
	{ MIME_TYPE_APPLICATION_EPUB,					D },
	{ MIME_TYPE_APPLICATION_EXCEL,					0 },
	{ MIME_TYPE_APPLICATION_GAMEBOY_ROM,			0 },
	{ MIME_TYPE_APPLICATION_GENESIS_ROM,			0 },
	{ MIME_TYPE_APPLICATION_GZIP,					U },
	{ MIME_TYPE_APPLICATION_IPHONE_APP,				0 },
	{ MIME_TYPE_APPLICATION_ISO9660,				U },
	{ MIME_TYPE_APPLICATION_JAR,					U },
	{ MIME_TYPE_APPLICATION_JAVASCRIPT,				U|D },
	{ MIME_TYPE_APPLICATION_JAVA_SER,				0 },
	{ MIME_TYPE_APPLICATION_JAVA_VM,				0 },
	{ MIME_TYPE_APPLICATION_LYX,					D },
	{ MIME_TYPE_APPLICATION_LZH,					U },
	{ MIME_TYPE_APPLICATION_MOBIPOCKET_EBOOK,		D },
	{ MIME_TYPE_APPLICATION_MSWORD,					D },
	{ MIME_TYPE_APPLICATION_MS_READER,				D },
	{ MIME_TYPE_APPLICATION_MS_SHORTCUT,			0 },
	{ MIME_TYPE_APPLICATION_N64_ROM,				0 },
	{ MIME_TYPE_APPLICATION_NES_ROM,				0 },
	{ MIME_TYPE_APPLICATION_OBJECT,					0 },
	{ MIME_TYPE_APPLICATION_OGG,					A },
	{ MIME_TYPE_APPLICATION_OPEN_PACKAGING_FORMAT,	U },
	{ MIME_TYPE_APPLICATION_PDF,					D },
	{ MIME_TYPE_APPLICATION_POSTSCRIPT,				D|I },
	{ MIME_TYPE_APPLICATION_POWERPOINT,				D },
	{ MIME_TYPE_APPLICATION_RAR,					U },
	{ MIME_TYPE_APPLICATION_RDF,					D },
	{ MIME_TYPE_APPLICATION_RSS,					D },
	{ MIME_TYPE_APPLICATION_SH,						U },
	{ MIME_TYPE_APPLICATION_SHAR,					U },
	{ MIME_TYPE_APPLICATION_SHOCKWAVE_FLASH,		V },
	{ MIME_TYPE_APPLICATION_SIT,					U },
	{ MIME_TYPE_APPLICATION_SNES_ROM,				0 },
	{ MIME_TYPE_APPLICATION_TAR,					U },
	{ MIME_TYPE_APPLICATION_TEX,					D },
	{ MIME_TYPE_APPLICATION_TEXINFO,				D },
	{ MIME_TYPE_APPLICATION_TROFF,					D },
	{ MIME_TYPE_APPLICATION_TROFF_MAN,				D },
	{ MIME_TYPE_APPLICATION_TROFF_ME,				D },
	{ MIME_TYPE_APPLICATION_TROFF_MS,				D },
	{ MIME_TYPE_APPLICATION_ZIP,					U },
	{ MIME_TYPE_AUDIO_BASIC,						A },
	{ MIME_TYPE_AUDIO_FLAC,							A },
	{ MIME_TYPE_AUDIO_MATROSKA,						A },
	{ MIME_TYPE_AUDIO_MIDI,							A },
	{ MIME_TYPE_AUDIO_MP4,							A },
	{ MIME_TYPE_AUDIO_MPEG,							A },
	{ MIME_TYPE_AUDIO_MPEGURL,						0 },
	{ MIME_TYPE_AUDIO_MS_ASF,						A },
	{ MIME_TYPE_AUDIO_OGG,							A },
	{ MIME_TYPE_AUDIO_PLAYLIST,						0 },
	{ MIME_TYPE_AUDIO_REALAUDIO,					A },
	{ MIME_TYPE_AUDIO_SPEEX,						A },
	{ MIME_TYPE_AUDIO_WAVE,							A },
	{ MIME_TYPE_IMAGE_BMP,							I },
	{ MIME_TYPE_IMAGE_GIF,							I },
	{ MIME_TYPE_IMAGE_JPEG,							I },
	{ MIME_TYPE_IMAGE_PNG,							I },
	{ MIME_TYPE_IMAGE_PSD,							I },
	{ MIME_TYPE_IMAGE_TGA,							I },
	{ MIME_TYPE_IMAGE_TIFF,							I },
	{ MIME_TYPE_IMAGE_XPM,							I },
	{ MIME_TYPE_MESSAGE_RFC822,						D },
	{ MIME_TYPE_TEXT_C,								0 },
	{ MIME_TYPE_TEXT_CALENDAR,						0 },
	{ MIME_TYPE_TEXT_CHDR,							0 },
	{ MIME_TYPE_TEXT_CPP,							0 },
	{ MIME_TYPE_TEXT_CPPHDR,						0 },
	{ MIME_TYPE_TEXT_CSS,							0 },
	{ MIME_TYPE_TEXT_CSV,							D },
	{ MIME_TYPE_TEXT_DIFF,							0 },
	{ MIME_TYPE_TEXT_HTML,							D },
	{ MIME_TYPE_TEXT_JAVA,							0 },
	{ MIME_TYPE_TEXT_LATEX,							D },
	{ MIME_TYPE_TEXT_LILYPOND,						D },
	{ MIME_TYPE_TEXT_PERL,							0 },
	{ MIME_TYPE_TEXT_PLAIN,							D },
	{ MIME_TYPE_TEXT_PYTHON,						0 },
	{ MIME_TYPE_TEXT_RTF,							D },
	{ MIME_TYPE_TEXT_XHTML,							D },
	{ MIME_TYPE_TEXT_XML,							D },
	{ MIME_TYPE_VIDEO_FLV,							V },
	{ MIME_TYPE_VIDEO_MATROSKA,						V },
	{ MIME_TYPE_VIDEO_MP4,							V },
	{ MIME_TYPE_VIDEO_MPEG,							V },
	{ MIME_TYPE_VIDEO_MSVIDEO,						V },
	{ MIME_TYPE_VIDEO_MS_ASF,						V },
	{ MIME_TYPE_VIDEO_OGG,							V },
	{ MIME_TYPE_VIDEO_OGM,							V },
	{ MIME_TYPE_VIDEO_QUICKTIME,					V },
};

#undef A
#undef V
#undef D
#undef I
#undef U

/**
 * Hash table yielding the media type flags from a MIME type.
 * Built dynamically from media_type_map[].
 */
static htable_t *share_media_types;

/**
 * Reset sha1_to_share
 */
static void
reinit_sha1_table(void)
{
	if G_UNLIKELY(NULL == sha1_to_share) {
		sha1_to_share = hikset_create(
			offsetof(shared_file_t, sha1), HASH_KEY_FIXED, SHA1_RAW_SIZE);
		hikset_thread_safe(sha1_to_share);
	} else {
		hikset_clear(sha1_to_share);
	}
}

void
shared_file_check(const shared_file_t * const sf)
{
	g_assert(sf);
	g_assert(SHARE_REBUILDING != sf);
	g_assert(SHARED_FILE_MAGIC == sf->magic);
	g_assert(sf->refcnt >= 0);
}

void
shared_file_name_check(const shared_file_t * const sf)
{
	g_assert((NULL != sf->name_nfc) ^ (0 == sf->name_nfc_len));
	g_assert((NULL != sf->name_canonic) ^ (0 == sf->name_canonic_len));
}

/**
 * Allocate a shared_file_t structure.
 */
static shared_file_t *
shared_file_alloc(void)
{
	shared_file_t *sf;

	WALLOC0(sf);
	sf->magic = SHARED_FILE_MAGIC;
	return sf;
}

static void
shared_file_deindex(shared_file_t *sf)
{
	shared_file_check(sf);
	shared_file_name_check(sf);

	if (SHARE_F_BASENAME & sf->flags) {
		if (shared_libfile.file_basenames != NULL) {
			htable_remove(shared_libfile.file_basenames, sf->name_nfc);
		}
	}
	sf->flags &= ~SHARE_F_BASENAME;

	/*
	 * The shared file might not be referenced by the current file_table
	 * either because it hasn't been build yet or because of a rescan.
	 */

	SHARED_LIBFILE_LOCK;

	if (
		shared_libfile.file_table != NULL &&
		sf->file_index > 0 &&
		sf->file_index <= shared_libfile.files_scanned &&
		sf == shared_libfile.file_table[sf->file_index - 1]
	) {
		g_assert(SHARE_F_INDEXED & sf->flags);
		shared_libfile.file_table[sf->file_index - 1] = NULL;
	}
	if (
		shared_libfile.sorted_file_table &&
		sf->sort_index > 0 &&
		sf->sort_index <= shared_libfile.files_scanned &&
		sf == shared_libfile.sorted_file_table[sf->sort_index - 1]
	) {
		g_assert(SHARE_F_INDEXED & sf->flags);
		shared_libfile.sorted_file_table[sf->sort_index - 1] = NULL;
	}

	sf->file_index = 0;
	sf->sort_index = 0;
	sf->flags &= ~SHARE_F_INDEXED;

	SHARED_LIBFILE_UNLOCK;

	/*
	 * Shared file is no longer indexed so it no longer belongs to the
	 * shared set and needs to be removed if it was referenced there.
	 */

	if (sf->sha1 != NULL && sha1_to_share != NULL) {
		shared_file_t *current;

		current = hikset_lookup(sha1_to_share, sf->sha1);
		if (current == sf) {
			hikset_remove(sha1_to_share, sf->sha1);
		}
	}
}

/**
 * Dispose of a shared_file_t structure and nullify the pointer.
 */
static void
shared_file_free(shared_file_t **sf_ptr)
{
	g_assert(sf_ptr);
	if (*sf_ptr) {
		shared_file_t *sf = *sf_ptr;

		g_assert(0 == sf->refcnt);

		g_assert_log(0 == (sf->flags & SHARE_F_FILEINFO),
			"%s(): invoked on file used by a fileinfo", G_STRFUNC);

		g_assert_log(0 == (sf->flags & SHARE_F_INDEXED),
			"%s(): invoked on file still indexed", G_STRFUNC);

		atom_sha1_free_null(&sf->sha1);
		atom_tth_free_null(&sf->tth);
		atom_str_free_null(&sf->relative_path);
		atom_str_free_null(&sf->file_path);
		atom_str_free_null(&sf->name_nfc);
		atom_str_free_null(&sf->name_canonic);
		sf->magic = 0;

		WFREE(sf);
		*sf_ptr = NULL;
	}
}

/**
 * Set canonic, NFC and NFKC normalized names.
 *
 * @return whether an error occurred
 */
static bool
shared_file_set_names(shared_file_t *sf, const char *filename)
{
  	shared_file_check(sf);	
	g_assert(NULL == sf->name_nfc);
	g_assert(NULL == sf->name_canonic);

	/* Set the NFC normalized name. */
	{	
		char *name = filename_to_utf8_normalized(filename, UNI_NORM_NETWORK);
		sf->name_nfc = atom_str_get(name);
		G_FREE_NULL(name);
	}

	/*
	 * Set the NFKC normalized name. Also prepend the relative path
	 * if enabled. Queries will be matched against this string.
	 */
	{
		char *name, *name_canonic;

		if (
			GNET_PROPERTY(search_results_expose_relative_paths) &&
			sf->relative_path
		) {
			name = g_strconcat(sf->relative_path, " ", sf->name_nfc, NULL);
		} else {
			name = deconstify_char(sf->name_nfc);
		}
		name_canonic = UNICODE_CANONIZE(name);
		sf->name_canonic = atom_str_get(name_canonic);
		if (name_canonic != name) {
			HFREE_NULL(name_canonic);
		}
		if (name != sf->name_nfc) {
			G_FREE_NULL(name);
		}
	}

	sf->name_nfc_len = strlen(sf->name_nfc);
	sf->name_canonic_len = strlen(sf->name_canonic);

	shared_file_name_check(sf);

	if (0 == sf->name_nfc_len || 0 == sf->name_canonic_len) {
		g_warning("%s(): normalized filename is an empty string \"%s\" "
			"(NFC=\"%s\", canonic=\"%s\")",
			G_STRFUNC, filename, sf->name_nfc, sf->name_canonic);
		return TRUE;
	}
	return FALSE;		/* OK, no error */
}

static const uint FILENAME_CLASH = -1;		/**< Indicates basename clashes */
static const uint PARTIAL_FILE = -2;		/**< Indicates partial file */
static const uint SPECIAL_FILE = -3;		/**< Special served files */

/**
 * Initialize special file entry, returning shared_file_t structure if
 * the file exists, NULL otherwise.
 */
static G_GNUC_COLD shared_file_t *
share_special_load(const struct special_file *sp)
{
	FILE *f;
	int idx = 0;
	char *tmp;
	shared_file_t *sf = NULL;
	file_path_t fp[4];
	unsigned length = 0;

	tmp = get_folder_path(PRIVLIB_PATH, NULL);
	if (tmp != NULL)
		file_path_set(&fp[length++], tmp, sp->file);

	file_path_set(&fp[length++], settings_config_dir(), sp->file);
	file_path_set(&fp[length++], PRIVLIB_EXP, sp->file);
#ifndef OFFICIAL_BUILD
	file_path_set(&fp[length++], PACKAGE_EXTRA_SOURCE_DIR, sp->file);
#endif

	g_assert(length <= G_N_ELEMENTS(fp));
	
	f = file_config_open_read_norename_chosen(sp->what, fp, length, &idx);

	if (NULL == f)
		goto done;

	/*
	 * Create fake special file sharing structure, so that we can
	 * upload it if requested.
	 */

	sf = shared_file_alloc();
	sf->flags |= SHARE_F_SPECIAL;
	sf->file_index = SPECIAL_FILE;

	{
		char *filename = make_pathname(fp[idx].dir, fp[idx].name);
		sf->file_path = atom_str_get(filename);
		HFREE_NULL(filename);
	}
	if (shared_file_set_names(sf, sp->file)) {
		shared_file_free(&sf);
	} else {
		sf->mime_type = sp->type;
	}

	fclose(f);

done:
	HFREE_NULL(tmp);

	return sf;
}

/**
 * Apply query string to the library.
 *
 * @param query			the query string to apply
 * @param callback		routine to call on each hit
 * @param user_data		opaque context passed to callback
 * @param max_res		maximum number of results
 * @param flags			operating flags (SHARE_FM_* flags)
 * @param qhv			query hash vector, filled with query words if not NULL
 */
void
shared_files_match(const char *query,
	st_search_callback callback, void *user_data,
	int max_res, uint32 flags, query_hashvec_t *qhv)
{
	int n;
	int remain;
	search_table_t *gt, *pt;
	bool partials = booleanize(flags & SHARE_FM_PARTIALS);
	bool g2_query = booleanize(flags & SHARE_FM_G2);

	/*
	 * Take snapshots of the global search and partial tables, in case
	 * they are reset by a background rescan.
	 */

	SHARED_LIBFILE_LOCK;
	gt = st_refcnt_inc(shared_libfile.search_table);
	pt = partials ? st_refcnt_inc(shared_libfile.partial_table) : NULL;
	SHARED_LIBFILE_UNLOCK;

	/*
	 * First search from the library.
	 */

	n = st_search(gt, query, callback, user_data, max_res, qhv);


	gnet_stats_count_general(g2_query ? GNR_LOCAL_G2_HITS : GNR_LOCAL_HITS, n);
	remain = max_res - n;

	/*
	 * Then if we still can supply some hits, look whether we have a partial
	 * file matching.
	 *
	 * Matching on partials is done only when users request that explicitly
	 * in their query (through the GGEP "PR" key) and when we serve partial
	 * files (PFSP server) and they configured answering to partial requests.
	 */

	if (partials && remain > 0 && share_can_answer_partials()) {
		n = st_search(pt, query, callback, user_data, remain, NULL);
		gnet_stats_count_general(
			g2_query ? GNR_LOCAL_G2_PARTIAL_HITS : GNR_LOCAL_PARTIAL_HITS, n);
	}

	st_free(&gt);
	st_free(&pt);
}

/**
 * Initialize the special files we're sharing.
 */
static G_GNUC_COLD void
share_special_init(void)
{
	uint i;

	special_names = htable_create(HASH_KEY_STRING, 0);

	for (i = 0; i < G_N_ELEMENTS(specials); i++) {
		shared_file_t *sf = share_special_load(&specials[i]);
		if (sf != NULL)
			htable_insert(special_names, specials[i].path, shared_file_ref(sf));
	}
}

/**
 * Look up a possibly shared special file, updating the entry with current
 * file size and modification time.
 *
 * @param path	the URL path on the server (case sensitive, of course)
 *
 * @return the shared file information if there is something shared at path,
 * or NULL if the path is invalid.
 */
shared_file_t *
shared_special(const char *path)
{
	shared_file_t *sf;
	filestat_t file_stat;

	sf = htable_lookup(special_names, path);

	if (sf == NULL)
		return NULL;

	if (-1 == stat(sf->file_path, &file_stat)) {
		g_warning("can't stat %s: %m", sf->file_path);
		return NULL;
	}

	if (!S_ISREG(file_stat.st_mode)) {
		g_warning("file %s is no longer a plain file", sf->file_path);
		return NULL;
	}

	/*
	 * Update information in case the file changed since the last time
	 * we served it.
	 */

	sf->file_size = file_stat.st_size;
	sf->mtime = file_stat.st_mtime;
	sf->ctime = file_stat.st_ctime;

	return sf;
}

/**
 * Given a valid index, returns the `struct shared_file' entry describing
 * the shared file bearing that index if found, NULL if not found (invalid
 * index) and SHARE_REBUILDING when we're rebuilding the library.
 *
 * The returned file is reference-counted and the caller needs to call
 * shared_file_unref() when it is done with the file.
 *
 * @return shared file info for index `idx', or NULL if none.
 */
shared_file_t *
shared_file(uint idx)
{
	shared_file_t * sf;

	SHARED_LIBFILE_LOCK;

	if (NULL == shared_libfile.file_table)		/* Rebuilding the library! */
		sf = SHARE_REBUILDING;
	else if (idx < 1 || idx > shared_libfile.files_scanned)
		sf = NULL;
	else {
		sf = shared_libfile.file_table[idx - 1];
		if (sf != NULL)
			shared_file_ref(sf);
	}

	SHARED_LIBFILE_UNLOCK;

	return sf;
}

/**
 * Given a valid index, returns the `struct shared_file' entry describing
 * the shared file bearing that index if found, NULL if not found (invalid
 * index) and SHARE_REBUILDING when we're rebuilding the library.
 *
 * The returned file is reference-counted and the caller needs to call
 * shared_file_unref() when it is done with the file.
 *
 * @return shared file info for index `idx', or NULL if none.
 */
shared_file_t *
shared_file_sorted(uint idx)
{
	shared_file_t *sf;

	SHARED_LIBFILE_LOCK;

	if (NULL == shared_libfile.sorted_file_table)	/* Rebuilding library! */
		sf = SHARE_REBUILDING;
	else if (idx < 1 || idx > shared_libfile.files_scanned)
		sf = NULL;
	else {
		sf = shared_libfile.sorted_file_table[idx - 1];
		if (sf != NULL)
			shared_file_ref(sf);
	}

	SHARED_LIBFILE_UNLOCK;

	return sf;
}

/**
 * Get index of shared file identified by its name.
 *
 * @return index > 0 if found, 0 if file is not known.
 */
static uint
shared_file_get_index(const char *filename)
{
	uint idx;

	assert_shared_libfile_locked();

	idx = pointer_to_uint(
		htable_lookup(shared_libfile.file_basenames, filename));

	if G_UNLIKELY(FILENAME_CLASH == idx) {
		idx = 0;
	} else {
		/* NB: index can be 0 if no file bearing that name is shared */
		g_assert_log(idx <= shared_libfile.files_scanned,
			"idx=%u, files_scanned=%lu",
			idx, (ulong) shared_libfile.files_scanned);
	}

	return idx;
}

/**
 * Given a file basename, returns the `struct shared_file' entry describing
 * the shared file bearing that basename, provided it is unique, NULL if
 * we either don't have a unique filename or SHARE_REBUILDING if the library
 * is being rebuilt.
 *
 * @return ref-counted file if not NULL or not SHARE_REBUILDING.
 */
shared_file_t *
shared_file_by_name(const char *filename)
{
	shared_file_t *sf;
	uint idx;

	SHARED_LIBFILE_LOCK;

	if G_UNLIKELY(NULL == shared_libfile.file_table) {
		sf = SHARE_REBUILDING;
	} else {
		g_assert(shared_libfile.file_basenames != NULL);
		idx = shared_file_get_index(filename);
		if (idx > 0) {
			sf = shared_libfile.file_table[idx - 1];
			shared_file_check(sf);
			shared_file_ref(sf);
		} else {
			sf = NULL;
		}
	}

	SHARED_LIBFILE_UNLOCK;

	return sf;
}

static void
free_extensions_helper(const void *key, void *unused_data)
{
	(void) unused_data;
	atom_str_free(key);
}

/**
 * Free existing extensions
 */
static void
free_extensions(void)
{
	if (extensions) {
		hset_foreach(extensions, free_extensions_helper, NULL);
		hset_free_null(&extensions);
	}
}

/**
 * Get the file extensions to scan.
 */
void
parse_extensions(const char *str)
{
	char **exts = g_strsplit(str, ";", 0);
	char *x, *s;
	uint i;

	free_extensions();
	extensions = hset_create_any(ascii_strcase_hash, NULL, ascii_strcase_eq);

	for (i = 0; exts[i]; i++) {
		char c;

		s = exts[i];
		while ((c = *s) == '.' || c == '*' || c == '?' || is_ascii_blank(c))
			s++;

		if (c) {

			for (x = strchr(s, '\0'); x-- != s; /* NOTHING */) {
				if ((c = *x) == '*' || c == '?' || is_ascii_blank(c))
					*x = '\0';
				else
					break;
			}

			if (*s && !hset_contains(extensions, s)) {
				const void *key = atom_str_get(s);
				hset_insert(extensions, key);
			}
		}
	}

	g_strfreev(exts);
}

/**
 * Release shared dirs.
 */
static void
shared_dirs_free(void)
{
	pslist_t *sl;

	if (!shared_dirs)
		return;

	for (sl = shared_dirs; sl; sl = pslist_next(sl)) {
		atom_str_free(sl->data);
	}
	pslist_free_null(&shared_dirs);
}

/**
 * Update the property holding the shared directories.
 */
void
shared_dirs_update_prop(void)
{
	pslist_t *sl;
	str_t *s;

	s = str_new(0);

	for (sl = shared_dirs; sl != NULL; sl = pslist_next(sl)) {
	    str_cat(s, sl->data);
		if (pslist_next(sl) != NULL)
			str_putc(s, G_SEARCHPATH_SEPARATOR);
	}

	gnet_prop_set_string(PROP_SHARED_DIRS_PATHS, str_2c(s));

	str_destroy(s);
}

/**
 * Parses the given string and updated the internal list of shared dirs.
 * The given string was completely parsed, it returns TRUE, otherwise
 * it returns FALSE.
 */
bool
shared_dirs_parse(const char *str)
{
	char **dirs = g_strsplit(str, G_SEARCHPATH_SEPARATOR_S, 0);
	bool ret = TRUE;
	uint i;

	/* FIXME: ESCAPING! */

	shared_dirs_free();

	for (i = 0; dirs[i]; i++) {
		if (is_directory(dirs[i]))
			shared_dirs = pslist_prepend(shared_dirs,
								deconstify_char(atom_str_get(dirs[i])));
		else
			ret = FALSE;
	}

	shared_dirs = pslist_reverse(shared_dirs);
	g_strfreev(dirs);

	return ret;
}

/**
 * Add directory to the list of shared directories.
 */
void
shared_dir_add(const char *pathname)
{
	if (is_directory(pathname)) {
		if (GNET_PROPERTY(share_debug) > 0) {
			g_debug("%s: adding pathname=\"%s\"", G_STRFUNC, pathname);
		}
		shared_dirs = pslist_append(shared_dirs,
						deconstify_char(atom_str_get(pathname)));
	} else {
		if (GNET_PROPERTY(share_debug) > 0) {
			g_debug("%s: NOT adding pathname=\"%s\"", G_STRFUNC, pathname);
		}
	}
	shared_dirs_update_prop();
}

/**
 * Add one more reference to a shared_file_t.
 * @return its argument, for convenience.
 */
shared_file_t *
shared_file_ref(const shared_file_t *sf)
{
	shared_file_t *wsf = deconstify_pointer(sf);

	shared_file_check(sf);

	atomic_int_inc(&wsf->refcnt);
	return wsf;
}

/**
 * Remove one reference to a shared_file_t, freeing entry if there are
 * no reference left. The pointer itself is nullified.
 *
 * To simplify user code, we gracefully ignore the SHARE_REBUILDING argument.
 */
void
shared_file_unref(shared_file_t **sf_ptr)
{
	g_assert(sf_ptr != NULL);
	shared_file_t *sf = *sf_ptr;

	if G_UNLIKELY(SHARE_REBUILDING == sf) {
		*sf_ptr = NULL;
	} else if (sf != NULL) {
		shared_file_check(sf);
		g_assert(sf->refcnt > 0);

		if (atomic_int_dec_is_zero(&sf->refcnt))
			shared_file_free(&sf);

		*sf_ptr = NULL;
	}
}

/**
 * Remove one reference to a shared_file_t, used in a fileinfo.
 * The pointer is nullified.
 */
void
shared_file_fileinfo_unref(shared_file_t **sf_ptr)
{
	shared_file_t *sf;

	g_assert(sf_ptr != NULL);

	if (NULL != (sf = *sf_ptr)) {
		g_assert(sf->flags & SHARE_F_FILEINFO);
		sf->flags &= ~SHARE_F_FILEINFO;		/* Clear bit before freeing */
		shared_file_unref(sf_ptr);
	}
}

/**
 * Is file too big to be shared on Gnutella?
 *
 * Note: The original purpose was to avoid files larger than 2^32-1 bytes.
 *		 Keep it just in case that a platform has an fileoffset_t with more than
 *		 64 bits.
 */
static inline bool
too_big_for_gnutella(fileoffset_t size)
{
	g_return_val_if_fail(size >= 0, TRUE);
	return size + (filesize_t) 0 > (filesize_t) -1 + (fileoffset_t) 0;
}

/**
 * Checks whether it's OK to share the pathname with respect to special
 * characters in the string. As the database stores records line-by-line,
 * newline characters in the filename are not acceptable.
 *
 * @return	If the pathname contains ASCII control characters, TRUE is
 *			returned. Otherwise, the pathname is considered OK and FALSE
 *			is returned.
 */
static bool
contains_control_chars(const char *pathname)
{
	const char *s;

	for (s = pathname; *s != '\0'; s++) {
		if (is_ascii_cntrl(*s))
			return TRUE;
	}
	return FALSE;
}

/**
 * Extracts the relative path from a pathname relative to base_dir. If
 * base_dir and pathname do not overlap, NULL is returned. The resulting
 * is converted to UTF-8 NFC and returned as an atom.
 *
 * @param base_dir The base directory.
 * @param pathname A pathname that is relative to "base_dir".
 * @return A string atom holding the relative path or NULL.
 */
static const char *
get_relative_path(const char *base_dir, const char *pathname)
{
	const char *s, *relative_path = NULL;

	s = is_strprefix(pathname, base_dir);
	if (s) {
		s = skip_dir_separators(s);
		if ('\0' != s[0]) {
			char *nfc_str;

			nfc_str = filename_to_utf8_normalized(s, UNI_NORM_NETWORK);
			normalize_dir_separators(nfc_str);
			relative_path = atom_str_get(nfc_str);
			G_FREE_NULL(nfc_str);
		}
	}
	return relative_path;
}

/**
 * Verify that a file extension is valid for sharing
 *
 * @param filename  The name of the file to check.
 * @return TRUE if the file should be shared, FALSE if not.
 */
static bool
shared_file_valid_extension(const char *filename)
{
	const char *filename_ext;

	if G_UNLIKELY(NULL == extensions)
		return FALSE;

	if (
		1 == hset_count(extensions) &&
		hset_contains(extensions, "--all--")
	) {
		/*
		 * An extension "--all--" matches all files, even those that don't
		 * have any extension. [Original patch by Zygo Blaxell].
		 */
		return TRUE;
	}

	filename_ext = strrchr(filename, '.');
	if (filename_ext) {
		/*
		 * Filenames without any extension are not shared, unless
		 * "--all--" is used.
		 */	

		filename_ext++;	/* skip the dot */

		/* 
		 * Match the file extension (if any) against the extensions list.
		 * All valid extensions start with '.'.  Matching is case-insensitive
		 */

		if (hset_contains(extensions, filename_ext))
			return TRUE;
	}

	return FALSE;
}

/**
 * @param relative_path The relative path of the file or NULL.
 * @param pathname The absolute pathname of the file.
 * @param sb A "stat buffer" that was initialized with stat().
 *
 * return On success a shared_file_t for the file is returned. Otherwise,
 *		  NULL is returned.
 */
static shared_file_t * 
share_scan_add_file(const char *relative_path,
	const char *pathname, const filestat_t *sb)
{
	shared_file_t *sf;
	const char *name;

	g_assert(is_absolute_path(pathname));
	g_assert(sb);
	g_return_val_if_fail(S_ISREG(sb->st_mode), NULL);

	if (0 == sb->st_size) {
		if (GNET_PROPERTY(share_debug) > 5)
			g_warning("not sharing empty file: \"%s\"", pathname);
		return NULL;
	}

	if (too_big_for_gnutella(sb->st_size)) {
		g_warning("file is too big to be shared: \"%s\"", pathname);
		return NULL;
	}

	if (contains_control_chars(pathname)) {
		g_warning("not sharing filename with control characters: "
				"\"%s\"", pathname);
		return NULL;
	}

	if (!shared_file_valid_extension(pathname))
		return NULL;

	name = filepath_basename(pathname);

	if (GNET_PROPERTY(share_debug) > 5)
		g_debug("%s: pathname=\"%s\"", G_STRFUNC, pathname);

	sf = shared_file_alloc();
	sf->file_path = atom_str_get(pathname);
	sf->relative_path = relative_path ? atom_str_get(relative_path) : NULL;
	sf->file_size = sb->st_size;
	sf->mtime = sb->st_mtime;
	sf->ctime = sb->st_ctime;

	if (shared_file_set_names(sf, name)) {
		shared_file_free(&sf);
		return NULL;
	}

	if (spam_check_filename_size(sf->name_nfc, sf->file_size)) {
		g_warning("file \"%s\" is listed as spam (Name)", sf->name_nfc);
		shared_file_free(&sf);
		return NULL;
	}

	sf->mime_type = mime_type_from_filename(sf->name_nfc);

	if (!sha1_is_cached(sf)) {
		int ret;

		/*
		 * In the "tmp" directory, don't share files that have a trailer.
		 * It's probably a file being downloaded, and which is not complete
		 * yet.  This check is necessary in case they chose to share their
		 * downloading directory...
		 */

		ret = file_info_has_trailer(pathname);
		switch (ret) {
		case 1:
			/*
			 * It's probably a file being downloaded, and which
			 * is not complete yet. This check is necessary in
			 * case they choose to share their downloading
			 * directory...
			 */
			g_warning("will not share partial file \"%s\"", pathname);
			/* FALL THROUGH */
		case -1:
			shared_file_free(&sf);
			return NULL;
		}
	}
	
	/*
	 * NOTE: An `else'-clause here would be if the file WAS found in the
	 * sha1_cache.  Good place to set the SHA1 in "sf".
	 */

	return sf;
}

/**
 * Check whether the given directory is one which should never be shared.
 * This is not meant to be exhaustive but test for common configuration
 * mistakes.
 */
static bool
directory_is_unshareable(const char *dir)
{
	g_assert(dir);

	/* Explicitly checking is_same_file() for TRUE to ignore errors (-1)
	 * probably caused by non-existing files or missing permission.
	 */
	if (TRUE == is_same_file(dir, "/")) {
		g_warning("refusing to share root directory: %s", dir);
		return TRUE;
	}

	if (TRUE == is_same_file(dir, settings_home_dir())) {
		g_warning("refusing to share home directory: %s", dir);
		return TRUE;
	}

	if (TRUE == is_same_file(dir, settings_config_dir())) {
		g_warning("refusing to share directory for configuration data: %s",
			dir);
		return TRUE;
	}

	if (
		!is_null_or_empty(GNET_PROPERTY(save_file_path)) &&
		TRUE == is_same_file(dir, GNET_PROPERTY(save_file_path))
	) {
		g_warning("refusing to share directory for incomplete files: %s", dir);
		return TRUE;
	}

	if (TRUE == is_same_file(dir, GNET_PROPERTY(bad_file_path))) {
		g_warning("refusing to share directory for corrupted files: %s", dir);
		return TRUE;
	}

	return FALSE;	/* No objection */
}

enum recursive_scan_magic { RECURSIVE_SCAN_MAGIC = 0x16926d87U };

struct recursive_scan {
	enum recursive_scan_magic magic;	/**< Magic number. */
	struct bgtask *task;
	DIR *directory;
	const char *base_dir;		/* string atom */
	const char *current_dir;	/* string atom */
	const char *relative_path;	/* string atom */
	time_t start_time;			/* when scanning started */
	slist_t *base_dirs;			/* list of string atoms */
	slist_t *sub_dirs;			/* list of g_malloc()ed strings */
	slist_t *shared_files;		/* list of struct shared_file */
	slist_t *partial_files;		/* list of struct shared_file */
	slist_iter_t *iter;			/* list iterator */
	htable_t *words;			/* records words making up filenames, for QRP */
	htable_t *basenames;		/* known file basenames */
	pslist_t *shared;				/* the new shared_files variable */
	shared_file_t **files;		/* the new file_table, sorted by mtime */
	shared_file_t **sorted;		/* the new sorted_file_table, sorted by name */
	shared_file_t **ftable;		/* cloned file_table, contains ref-counted sf */
	search_table_t *search_tb;	/* the new search table */
	search_table_t *partial_tb;	/* the new partial table */
	uint64 files_scanned;		/* amount of files shared in the library */
	uint64 bytes_scanned;		/* size of the library */
	int idx;					/* iterating index */
	int ticks;					/* ticks used */
	size_t ftable_capacity;		/* Amount of entries in ftable[] */
};

static inline void
recursive_scan_check(const struct recursive_scan * const ctx)
{
	g_assert(ctx);
	g_assert(RECURSIVE_SCAN_MAGIC == ctx->magic);
	g_assert(ctx->base_dirs != NULL);
	g_assert(ctx->sub_dirs != NULL);
	g_assert(ctx->shared_files != NULL);
	g_assert(ctx->partial_files != NULL);
}

static struct recursive_scan *
recursive_scan_new(const pslist_t *base_dirs, time_t now)
{
	struct recursive_scan *ctx;
	const pslist_t *iter;

	WALLOC0(ctx);
	ctx->magic = RECURSIVE_SCAN_MAGIC;
	ctx->start_time = now;
	ctx->base_dirs = slist_new();
	ctx->sub_dirs = slist_new();
	ctx->shared_files = slist_new();
	ctx->partial_files = slist_new();
	ctx->words = htable_create(HASH_KEY_STRING, 0);
	ctx->basenames = htable_create(HASH_KEY_STRING, 0);
	for (iter = base_dirs; NULL != iter; iter = pslist_next(iter)) {
		const char *dir = atom_str_get(iter->data);
		slist_append(ctx->base_dirs, deconstify_char(dir));
	}
	return ctx;
}

static void
recursive_scan_closedir(struct recursive_scan *ctx)
{
	recursive_scan_check(ctx);

	if (GNET_PROPERTY(share_debug) > 6 && ctx->current_dir != NULL)
		g_debug("SHARE leaving directory \"%s\"", ctx->current_dir);

	atom_str_free_null(&ctx->relative_path);
	atom_str_free_null(&ctx->current_dir);
	if (ctx->directory) {
		closedir(ctx->directory);
		ctx->directory = NULL;
	}
}

static void recursive_sf_unref(void *o)
{
	shared_file_t *sf = o;

	shared_file_check(sf);
	shared_file_unref(&sf);
}

/**
 * Encapsulation of hfree() in case TRACK_MALLOC is defined and hfree() is
 * really a macro, not a function.
 */
static void
do_hfree(void *p)
{
	hfree(p);
}

static void
scan_base_dir_free(void *data)
{
	/*
	 * We need this wrapper when compiling with -DTRACK_ATOMS since
	 * atom_str_free() becomes a macro.
	 */
	atom_str_free(data);
}


/**
 * Free the background task context for library / QRP rebuilds.
 *
 * This routine is invoked by the background task layer when the task is
 * being terminated.
 */
static void
recursive_scan_context_free(void *data)
{
	pslist_t *sl;
	struct recursive_scan *ctx = data;

	recursive_scan_check(ctx);

	recursive_scan_closedir(ctx);

	slist_iter_free(&ctx->iter);
	slist_free_all(&ctx->base_dirs, scan_base_dir_free);
	slist_free_all(&ctx->sub_dirs, do_hfree);
	slist_free_all(&ctx->shared_files, recursive_sf_unref);
	slist_free_all(&ctx->partial_files, recursive_sf_unref);

	htable_free_null(&ctx->basenames);
	st_free(&ctx->search_tb);
	st_free(&ctx->partial_tb);
	atom_str_free_null(&ctx->base_dir);
	qrp_dispose_words(&ctx->words);

	HFREE_NULL(ctx->files);
	HFREE_NULL(ctx->sorted);

	if (ctx->ftable != NULL) {
		size_t i;

		for (i = 0; i < ctx->ftable_capacity; i++) {
			shared_file_unref(&ctx->ftable[i]);
		}

		XFREE_NULL(ctx->ftable);
	}

	for (sl = ctx->shared; sl; sl = pslist_next(sl)) {
		shared_file_t *sf = sl->data;

		shared_file_check(sf);
		shared_file_unref(&sf);
	}
	pslist_free_null(&ctx->shared);

	ctx->task = NULL;
	ctx->magic = 0;
	WFREE(ctx);
}

/**
 * Free list of shared files and nullify its pointer.
 */
static void
share_list_free_null(pslist_t **slist)
{
	pslist_t *sl;

	for (sl = *slist; sl; sl = pslist_next(sl)) {
		shared_file_t *sf = sl->data;

		shared_file_check(sf);
		shared_file_unref(&sf);
	}
	pslist_free_null(slist);
}

/**
 * Free up memory used by the shared library.
 */
static void
share_free(void)
{
	st_free(&shared_libfile.search_table);
	htable_free_null(&shared_libfile.file_basenames);
	share_list_free_null(&shared_libfile.shared_files);
	HFREE_NULL(shared_libfile.file_table);
	HFREE_NULL(shared_libfile.sorted_file_table);
}

/**
 * Sort function - shared files by ascending mtime (oldest first). 
 */
static int
shared_file_sort_by_mtime(const void *f1, const void *f2)
{
	const shared_file_t * const *sfp1 = f1, * const *sfp2 = f2;
	const shared_file_t *sf1 = *sfp1, *sf2 = *sfp2;
	time_t t1, t2;

	/* We don't use shared_file_check() here because it would be
	 * the dominating factor for the sorting time. */
	g_assert(SHARED_FILE_MAGIC == sf1->magic);
	g_assert(SHARED_FILE_MAGIC == sf2->magic);

	t1 = sf1->mtime;
	t2 = sf2->mtime;
	return CMP(t1, t2);
}

static inline int
cmp_strings(const char *a, const char *b)
{
	if (a && b) {
		return a == b ? 0 : strcmp(a, b);
	} else {
		return a ? 1 : (b ? -1 : 0);
	}
}

/**
 * Sort function - shared files by name lexicographic order.
 */
static int
shared_file_sort_by_name(const void *f1, const void *f2)
{
	const shared_file_t * const *sfp1 = f1, * const *sfp2 = f2;
	const shared_file_t *sf1 = *sfp1, *sf2 = *sfp2;
	int ret;

	/* We don't use shared_file_check() here because it would be
	 * the dominating factor for the sorting time. */
	g_assert(SHARED_FILE_MAGIC == sf1->magic);
	g_assert(SHARED_FILE_MAGIC == sf2->magic);

	if (GNET_PROPERTY(search_results_expose_relative_paths)) {
		ret = cmp_strings(sf1->relative_path, sf2->relative_path);
	} else {
		ret = strcmp(sf1->file_path, sf2->file_path);
	}
	return 0 != ret ? ret : strcmp(sf1->name_nfc, sf2->name_nfc);
}

static void
recursive_scan_opendir(struct recursive_scan *ctx, const char * const dir)
{
	recursive_scan_check(ctx);
	g_assert(NULL == ctx->directory);
	g_assert(NULL == ctx->relative_path);
	g_assert(NULL == ctx->current_dir);

	g_return_if_fail('\0' != dir[0]);
	g_return_if_fail(is_absolute_path(ctx->base_dir));
	g_return_if_fail(is_absolute_path(dir));

	if (directory_is_unshareable(dir))
		return;

	/**
	 * FIXME: On Windows FindFirstFile/FindNextFile/FindClose
	 *		  must be used to get the Unicode filenames.		
	 */
	if (!(ctx->directory = opendir(dir))) {
		g_warning("can't open directory %s: %m", dir);
		return;
	}

	/* Get relative path if required */
	if (GNET_PROPERTY(search_results_expose_relative_paths)) {
		ctx->relative_path = get_relative_path(ctx->base_dir, dir);
	} else {
		ctx->relative_path = NULL;
	}
	ctx->current_dir = atom_str_get(dir);

	if (GNET_PROPERTY(share_debug) > 5)
		g_debug("SHARE scanning directory \"%s\"", ctx->current_dir);
}

static void
recursive_scan_readdir(struct recursive_scan *ctx)
{
	char *fullpath = NULL;
	struct dirent *dir_entry;

	recursive_scan_check(ctx);
	g_assert(ctx->directory);

	dir_entry = readdir(ctx->directory);
	if (dir_entry) {
		const char *filename = dir_entry_filename(dir_entry);
		filestat_t sb;

		if (GNET_PROPERTY(share_debug) > 19)
			g_debug("SHARE considering entry \"%s\"", filename);

		if ('.' == filename[0]) {
			/* Hidden file, or "." or ".." */
			goto finish;
		}

		sb.st_mode = dir_entry_mode(dir_entry);
		switch (sb.st_mode) {
		case 0:
		case S_IFREG:
		case S_IFDIR:
		case S_IFLNK:
			break;
		default:
			if (GNET_PROPERTY(share_debug)) {
				g_warning("skipping file of unknown type \"%s\" in \"%s\"",
					ctx->current_dir, filename);
			}
			goto finish;
		}

		if (
			S_ISLNK(sb.st_mode) &&
			GNET_PROPERTY(scan_ignore_symlink_dirs) &&
			GNET_PROPERTY(scan_ignore_symlink_regfiles)
		) {
			if (GNET_PROPERTY(share_debug) > 15) {
				g_debug("SHARE to-be-ignored symlink, discarding \"%s\"",
					filename);
			}
			goto finish;
		}

		if (
			S_ISREG(sb.st_mode) &&
			!shared_file_valid_extension(filename)
		) {
			if (GNET_PROPERTY(share_debug) > 15) {
				g_debug("SHARE unshared extension, discarding \"%s\"",
					filename);
			}
			goto finish;
		}

		ctx->ticks += 10;	/* Heavier work */

		fullpath = make_pathname(ctx->current_dir, filename);
		if (S_ISREG(sb.st_mode) || S_ISDIR(sb.st_mode)) {
			if (stat(fullpath, &sb)) {
				g_warning("stat() failed %s: %m", fullpath);
				goto finish;
			}
		} else if (!S_ISLNK(sb.st_mode)) {
			if (lstat(fullpath, &sb)) {
				g_warning("lstat() failed %s: %m", fullpath);
				goto finish;
			}

			if (
				S_ISLNK(sb.st_mode) &&
				GNET_PROPERTY(scan_ignore_symlink_dirs) &&
				GNET_PROPERTY(scan_ignore_symlink_regfiles)
			) {
				/*
				 * We check this again because dir_entry_mode() does not
				 * work everywhere.
				 */
				if (GNET_PROPERTY(share_debug) > 15) {
					g_debug("SHARE to-be-ignored symlink, discarding \"%s\"",
						filename);
				}
				goto finish;
			}
		}

		/* Get info on the symlinked file */
		if (S_ISLNK(sb.st_mode)) {
			if (stat(fullpath, &sb)) {
				g_warning("broken symlink %s: %m", fullpath);
				goto finish;
			}
			
			/*
			 * For symlinks, we check whether we are supposed to process
			 * symlinks for that type of entry, then either proceed or skip the
			 * entry.
			 */

			if (
				S_ISDIR(sb.st_mode) &&
				GNET_PROPERTY(scan_ignore_symlink_dirs)
			) {
				if (GNET_PROPERTY(share_debug) > 15)
					g_debug("SHARE discarding symlink dir \"%s\"", filename);
				goto finish;
			}
			if (
				S_ISREG(sb.st_mode) &&
				GNET_PROPERTY(scan_ignore_symlink_regfiles)
			) {
				if (GNET_PROPERTY(share_debug) > 15)
					g_debug("SHARE discarding symlink file \"%s\"", filename);
				goto finish;
			}
		}
		
		if (S_ISDIR(sb.st_mode)) {
			/* If a directory, add to list for later processing */
			slist_prepend(ctx->sub_dirs, fullpath);
			fullpath = NULL;
		} else if (S_ISREG(sb.st_mode)) {
			shared_file_t *sf;

			if (GNET_PROPERTY(share_debug) > 10)
				g_debug("SHARE adding file \"%s\"", filename);

			sf = share_scan_add_file(ctx->relative_path, fullpath, &sb);
			if (sf) {
				slist_append(ctx->shared_files, shared_file_ref(sf));
			}
		}
	} else {
		recursive_scan_closedir(ctx);
	}

finish:
	HFREE_NULL(fullpath);
	dir_entry_filename(NULL);	/* release memory */
}

/**
 * Callback invoked by the background task layer when a task is terminated.
 */
static void
recursive_scan_done(struct bgtask *bt, void *data, bgstatus_t status, void *arg)
{
	struct recursive_scan *ctx = data;

	recursive_scan_check(ctx);
	(void) arg;

	/*
	 * Tracing for debugging purposes.
	 */

	if (GNET_PROPERTY(share_debug)) {
		g_debug("terminating background task \"%s\" in %s, status=%s, "
			"ran %'lu ms (%s)",
			bg_task_name(bt), thread_name(), bgstatus_to_string(status),
			bg_task_wtime(bt), short_time_ascii(bg_task_wtime(bt) / 1000));
	}

	/*
	 * If background tasks are run in the main thread, then we need to
	 * explicitly reset the current task.  Otherwise, this is done in
	 * the library thread, which explicitly invokes the scheduler.
	 */

	if (THREAD_MAIN == share_thread_id) {
		struct share_thread_vars *v = &share_thread_vars;

		if (bt == v->task)
			v->task = NULL;
	}
}

/**
 * Signal handler for task termination.
 *
 * This handler is invoked from the background task scheduler and is therefore
 * run in the thread that is handling the background task...  Not necessarily
 * the main thread.
 */
static void
recursive_scan_sighandler(struct bgtask *bt, void *data, bgsig_t sig)
{
	struct recursive_scan *ctx = data;

	recursive_scan_check(ctx);
	g_assert(BG_SIG_TERM == sig);

	/*
	 * Tracing for debugging purposes.
	 */

	if (GNET_PROPERTY(share_debug)) {
		g_debug("cancelling background task \"%s\" in %s, currently in %s()",
			bg_task_name(bt), thread_name(), bg_task_step_name(bt));
	}
}

static void *
recursive_rescan_starting(void *unused)
{
	(void) unused;

	gnet_prop_set_boolean_val(PROP_LIBRARY_REBUILDING, TRUE);
	gnet_prop_set_timestamp_val(PROP_LIBRARY_RESCAN_STARTED, tm_time());

	return NULL;
}

/**
 * First step, intalling signal handler to trap task cancel.
 */
static bgret_t
recursive_scan_step_setup(struct bgtask *bt, void *data, int uticks)
{
	struct recursive_scan *ctx = data;

	recursive_scan_check(ctx);

	(void) uticks;

	/*
	 * The BG_SIG_TERM signal will be sent by the background task scheduler
	 * when the task is cancelled.
	 */

	bg_task_signal(bt, BG_SIG_TERM, recursive_scan_sighandler);

	atomic_bool_set(&share_rebuilding, TRUE);

	/*
	 * If we're not running in the main thread, we need to funnel this
	 * back as property changes can trigger GUI updates which we can't
	 * process from another thread until the GUI code is 100% thread-safe.
	 *		--RAM, 2013-10-29
	 */

	teq_safe_rpc(THREAD_MAIN, recursive_rescan_starting, NULL);

	bg_task_ticks_used(bt, 0);
	return BGR_NEXT;
}

/**
 * @return TRUE if finished.
 */
static bool 
recursive_scan_next_dir(struct recursive_scan *ctx)
{
	recursive_scan_check(ctx);

	bg_task_cancel_test(ctx->task);

	if (ctx->directory) {
		recursive_scan_readdir(ctx);
		return FALSE;
	} else if (slist_length(ctx->sub_dirs) > 0) {
		char *dir;

		dir = slist_shift(ctx->sub_dirs);
		recursive_scan_opendir(ctx, dir);
		HFREE_NULL(dir);
		return FALSE;
	} else if (slist_length(ctx->base_dirs) > 0) {
		atom_str_free_null(&ctx->base_dir);
		ctx->base_dir = slist_shift(ctx->base_dirs);
		recursive_scan_opendir(ctx, ctx->base_dir);
		return FALSE;
	} else {
		atom_str_free_null(&ctx->base_dir);
		return TRUE;
	}
}

static bgret_t
recursive_scan_step_compute(struct bgtask *bt, void *data, int ticks)
{
	struct recursive_scan *ctx = data;

	recursive_scan_check(ctx);

	ctx->ticks = 0;
	do {
		if (recursive_scan_next_dir(ctx)) {
			bg_task_ticks_used(bt, ctx->ticks);
			return BGR_NEXT;
		}
		ctx->ticks++;
	} while (ctx->ticks < ticks);

	return BGR_MORE;
}

static bgret_t
recursive_scan_step_compute_done(struct bgtask *bt, void *data, int ticks)
{
	struct recursive_scan *ctx = data;

	recursive_scan_check(ctx);
	(void) ticks;

	g_assert(NULL == ctx->shared);
	g_assert(NULL == ctx->search_tb);

	ctx->files_scanned = slist_length(ctx->shared_files);
	ctx->bytes_scanned = 0;
	ctx->search_tb = st_create();

	bg_task_ticks_used(bt, 0);
	return BGR_NEXT;
}

static bgret_t
recursive_scan_step_build_search_table(struct bgtask *bt, void *data, int ticks)
{
	struct recursive_scan *ctx = data;

	recursive_scan_check(ctx);

	ctx->ticks = 0;

	while (slist_length(ctx->shared_files) > 0) {
		const shared_file_t *sf;

		if (ctx->ticks++ >= ticks)
			return BGR_MORE;

		if (0 == (ctx->ticks & 0xf))
			bg_task_cancel_test(ctx->task);

		sf = slist_shift(ctx->shared_files);
		shared_file_check(sf);
		g_assert(!shared_file_is_partial(sf));
		g_assert(1 == sf->refcnt);
		ctx->bytes_scanned += sf->file_size;
		st_insert_item(ctx->search_tb, sf->name_canonic, sf);
		ctx->shared = pslist_prepend_const(ctx->shared, sf);
		upload_stats_enforce_local_filename(sf);
	}

	/* Compact the search table */
	st_compact(ctx->search_tb);
	ctx->ticks += 5;

	bg_task_ticks_used(bt, ctx->ticks);
	return BGR_NEXT;
}

static bgret_t
recursive_scan_step_build_file_table(struct bgtask *bt, void *data, int ticks)
{
	struct recursive_scan *ctx = data;
	pslist_t *sl;
	int i = 0;

	recursive_scan_check(ctx);
	g_assert(NULL == ctx->files);

	(void) ticks;

	if (0 == ctx->files_scanned)
		goto next;

	/*
	 * In order to quickly locate files based on indicies, build a table
	 * of all shared files.  This table is only accessible via shared_file().
	 * NB: file indicies start at 1, but indexing in table starts at 0.
	 *		--RAM, 08/10/2001
	 */

	HALLOC0_ARRAY(ctx->files, ctx->files_scanned);

	for (i = 0, sl = ctx->shared; sl; sl = pslist_next(sl)) {
		shared_file_t *sf = sl->data;

		shared_file_check(sf);
		g_assert(!(SHARE_F_INDEXED & sf->flags));
		g_assert(UNSIGNED(i) < ctx->files_scanned);
		g_assert(2 == sf->refcnt);	/* Added to search table */
		ctx->files[i++] = sf;
	}

	/* Sort file list by modification time to get a relatively stable index */
	vsort(ctx->files, ctx->files_scanned, sizeof ctx->files[0],
		shared_file_sort_by_mtime);

next:
	bg_task_ticks_used(bt, i / 10);
	ctx->idx = 0;				/* Prepares next step */

	return BGR_NEXT;
}

static bgret_t
recursive_scan_step_build_basenames(struct bgtask *bt, void *data, int ticks)
{
	struct recursive_scan *ctx = data;

	recursive_scan_check(ctx);

	ctx->ticks = 0;

	while (UNSIGNED(ctx->idx) < ctx->files_scanned) {
		shared_file_t *sf;
		uint val;
		int i = ctx->idx++;

		sf = ctx->files[i];
		shared_file_check(sf);

		/*
		 * Set file_index based on new sort order.
		 *
		 * We don't set SHARE_F_INDEXED yet, this will be done only when
		 * we're ready to install the new data structures we're still building.
		 */

		sf->file_index = i + 1;

		/*
		 * In order to transparently handle files requested with the wrong
		 * indices, for older servents that would not know how to handle a
		 * return code of "301 Moved" with a Location header, we keep track
		 * of individual basenames of files, recording the index of each file.
		 * As soon as there is a clash, we revoke the entry by storing
		 * FILENAME_CLASH instead, which cannot be a valid index.
		 *		--RAM, 06/06/2002
		 */

		val = pointer_to_uint(htable_lookup(ctx->basenames, sf->name_nfc));

		/*
		 * The following works because 0 cannot be a valid file index.
		 */

		val = (val != 0) ? FILENAME_CLASH : sf->file_index;
		htable_insert(ctx->basenames, sf->name_nfc, uint_to_pointer(val));

		if (ctx->ticks++ >= ticks)
			return BGR_MORE;

		if (0 == (ctx->ticks & 0xf))
			bg_task_cancel_test(ctx->task);
	}

	bg_task_ticks_used(bt, ctx->ticks);
	return BGR_NEXT;
}

static void *
recursive_update_scan_timing(void *data)
{
	struct recursive_scan *ctx = data;
	time_delta_t elapsed;

	recursive_scan_check(ctx);

	elapsed = delta_time(tm_time_exact(), ctx->start_time);
	elapsed = MAX(0, elapsed);

	gnet_prop_set_timestamp_val(PROP_LIBRARY_RESCAN_FINISHED, tm_time());
	gnet_prop_set_guint32_val(PROP_LIBRARY_RESCAN_DURATION, elapsed);

	return NULL;
}

static bgret_t
recursive_scan_step_update_scan_timing(struct bgtask *bt, void *data, int ticks)
{
	struct recursive_scan *ctx = data;

	recursive_scan_check(ctx);
	(void) ticks;

	/*
	 * If we're not running in the main thread, we need to funnel this
	 * back as property changes can trigger GUI updates which we can't
	 * process from another thread until the GUI code is 100% thread-safe.
	 *		--RAM, 2013-10-29
	 */

	teq_safe_rpc(THREAD_MAIN, recursive_update_scan_timing, ctx);

	bg_task_ticks_used(bt, 0);
	return BGR_NEXT;
}

static bgret_t
recursive_scan_step_build_sorted_table(struct bgtask *bt, void *data, int ticks)
{
	struct recursive_scan *ctx = data;
	int i = 0;

	recursive_scan_check(ctx);
	g_assert(NULL == ctx->sorted);

	(void) ticks;

	if (0 == ctx->files_scanned)
		goto next;

	ctx->sorted = HCOPY_ARRAY(ctx->files, ctx->files_scanned);

	vsort(ctx->sorted, ctx->files_scanned, sizeof ctx->sorted[0],
		shared_file_sort_by_name);

	/*
	 * Set the sort index used for sorted file listings
	 *
	 * Note that we're not setting SHARE_F_INDEXED yet because we don't know
	 * whether we're going to install the data structures we're building.
	 */

	for (i = 0; UNSIGNED(i) < ctx->files_scanned; i++) {
		shared_file_t *sf;

		sf = ctx->sorted[i];
		shared_file_check(sf);
		sf->sort_index = i + 1;
	}

next:
	bg_task_ticks_used(bt, i / 10);
	return BGR_NEXT;
}

static void *
recursive_install_shared(void *unused)
{
	(void) unused;

	gcu_gui_update_files_scanned();		/* Final view */
	gnet_prop_set_boolean_val(PROP_LIBRARY_REBUILDING, FALSE);

	return NULL;
}

/**
 * pslist_t iterator to mark shared file as no longer indexed.
 */
static void
shared_file_detach(void *data, void *unused)
{
	shared_file_t *sf = data;

	(void) unused;

	shared_file_check(sf);

	sf->flags &= ~SHARE_F_INDEXED;
	sf->file_index = 0;
	sf->sort_index = 0;
}

static bgret_t
recursive_scan_step_install_shared(struct bgtask *bt, void *data, int ticks)
{
	struct recursive_scan *ctx = data;
	size_t i;
	pslist_t *files;

	recursive_scan_check(ctx);
	g_assert(ctx->search_tb != NULL);

	(void) ticks;

	/*
	 * This step is "atomic" in that it cannot be interrupted by the background
	 * task scheduler.
	 *
	 * We're installing the shared library data structures we've been building
	 * in the previous steps, discarding the old ones.
	 */

	if (GNET_PROPERTY(share_debug) > 1) {
		int count = st_count(ctx->search_tb);
		g_debug("SHARE installing new search table (%d item%s)",
			count, plural(count));
	}

	/*
	 * Now that we are about to install the shared files, we can mark the
	 * entries as being indexed and basenamed.
	 *
	 * Note that no one else can reference the entries at this stage, only
	 * the file table and the search table (hence a refcount of 2).
	 */

	for (i = 0; i < ctx->files_scanned; i++) {
		shared_file_t *sf = ctx->files[i];

		shared_file_check(sf);
		g_assert(2 == sf->refcnt);

		sf->flags |= SHARE_F_INDEXED | SHARE_F_BASENAME;
	}

	SHARED_LIBFILE_LOCK;

	/*
	 * Don't let share_free() free the list of files whilst we hold the lock.
	 */

	files = shared_libfile.shared_files;
	shared_libfile.shared_files = NULL;
	share_free();

	/*
	 * All the files in the list are no longer indexed, as we create new
	 * shared file objects during our scan.  Other parts of the code may
	 * still have references on them, but they can realize that these
	 * references are stale by calling shared_file_indexed().
	 *
	 * Note that we do not need to call shared_file_deindex() here as we're
	 * about to replace all the data structures with fresh ones.
	 */

	pslist_foreach(files, shared_file_detach, NULL);

	shared_libfile.search_table			= ctx->search_tb;
	shared_libfile.file_basenames		= ctx->basenames;
	shared_libfile.shared_files			= ctx->shared;
	shared_libfile.file_table			= ctx->files;
	shared_libfile.sorted_file_table	= ctx->sorted;
	shared_libfile.files_scanned		= ctx->files_scanned;
	shared_libfile.bytes_scanned		= ctx->bytes_scanned;

	/*
	 * Reset these contextual variables, they are now held by the global ones.
	 */

	ctx->search_tb = NULL;
	ctx->basenames = NULL;
	ctx->shared = NULL;
	ctx->files = NULL;
	ctx->sorted = NULL;

	reinit_sha1_table();		/* Must happen whilst we hold the lock */

	SHARED_LIBFILE_UNLOCK;

	share_list_free_null(&files);

	/*
	 * If we're not running in the main thread, we need to funnel this
	 * back as property changes can trigger GUI updates which we can't
	 * process from another thread until the GUI code is 100% thread-safe.
	 *		--RAM, 2013-10-29
	 */

	teq_safe_rpc(THREAD_MAIN, recursive_install_shared, NULL);

	/*
	 * The next step is going to request the SHA1 of all the library files,
	 * which will fill again the known SHA1 cache.
	 */

	bg_task_ticks_used(bt, ctx->files_scanned / 10);
	ctx->idx = 0;		/* Prepare next step */
	return BGR_NEXT;
}

/**
 * Get a snapshot copy (atomically) of all the shared files currently
 * visible from the application.
 *
 * The ctx->ftable[] array is dynamically allocated to hold a reference-counted
 * shared file, or NULL if the file was de-indexed for some reason since it
 * was initially scanned.
 *
 * The ctx->ftable_capacity variable is set to hold the ftable[] capacity.
 */
static void
recursive_scan_load_ftable(struct recursive_scan *ctx)
{
	size_t i;

	g_assert(NULL == ctx->ftable);

	SHARED_LIBFILE_LOCK;

	ctx->ftable_capacity = shared_libfile.files_scanned;
	XMALLOC0_ARRAY(ctx->ftable, ctx->ftable_capacity);

	for (i = 0; i < ctx->ftable_capacity; i++) {
		shared_file_t *sf = shared_libfile.file_table[i];

		if (sf != NULL)
			ctx->ftable[i] = shared_file_ref(sf);
	}

	SHARED_LIBFILE_UNLOCK;

	ctx->ticks += ctx->ftable_capacity;
}

static bgret_t
recursive_scan_step_request_sha1(struct bgtask *bt, void *data, int ticks)
{
	struct recursive_scan *ctx = data;

	recursive_scan_check(ctx);

	/*
	 * The new library has been installed, we must now access the global
	 * variables.
	 */

	g_assert(NULL == ctx->files);		/* Indicates installation was done */

	ctx->ticks = 0;

	/*
	 * All the files are now shared and visible in the global data structures,
	 * yet we need to iterate to request SHA1 computation.
	 *
	 * To avoid taking the global lock for too long, we duplicate the
	 * file_table[] array, increment the reference on all the items, and
	 * then release the global lock.
	 *
	 * Iterating on the copy is OK because request_sha1() will do nothing if
	 * the file is no longer indexed.
	 */

	if (0 == ctx->idx)
		recursive_scan_load_ftable(ctx);

	while (UNSIGNED(ctx->idx) < ctx->ftable_capacity) {
		shared_file_t *sf;
		int i = ctx->idx++;

		sf = ctx->ftable[i];

		if (NULL == sf)
			continue;

		shared_file_check(sf);

		/*
		 * We must not change the file index after request_sha1() since this
		 * can synchronously call routines to set the SHA1 if it's known
		 * already.
		 */

		request_sha1(sf);

		if (ctx->ticks++ >= ticks)
			return BGR_MORE;

		if (0 == (ctx->ticks & 0xf))
			bg_task_cancel_test(ctx->task);
	}

	/* Done rebuilding the SHA1 table */
	atomic_bool_set(&share_rebuilding, FALSE);

	bg_task_ticks_used(bt, ctx->ticks);
	return BGR_NEXT;
}

/**
 * First step, intalling signal handler to trap task cancel.
 */
static bgret_t
recursive_scan_step_qrp_setup(struct bgtask *bt, void *data, int uticks)
{
	struct recursive_scan *ctx = data;

	recursive_scan_check(ctx);

	(void) uticks;

	/*
	 * The BG_SIG_TERM signal will be sent by the background task scheduler
	 * when the task is cancelled.
	 */

	bg_task_signal(bt, BG_SIG_TERM, recursive_scan_sighandler);

	bg_task_ticks_used(bt, 0);
	return BGR_NEXT;
}

static bgret_t
recursive_scan_step_load_partials(struct bgtask *bt, void *data, int ticks)
{
	struct recursive_scan *ctx = data;

	recursive_scan_check(ctx);
	(void) ticks;

	bg_task_cancel_test(ctx->task);

	if (share_can_answer_partials()) {
		hset_iter_t *iter;
		const void *item;

		hset_lock(partial_files);
		iter = hset_iter_new(partial_files);

		while (hset_iter_next(iter, &item)) {
			const shared_file_t *sf = item;
			slist_append(ctx->partial_files, shared_file_ref(sf));
		}

		hset_iter_release(&iter);
		hset_unlock(partial_files);
	}

	bg_task_ticks_used(bt, 0);
	return BGR_NEXT;
}

static bgret_t
recursive_scan_step_build_partial_table(struct bgtask *bt,
	void *data, int ticks)
{
	struct recursive_scan *ctx = data;

	recursive_scan_check(ctx);

	ctx->ticks = 0;

	if (NULL == ctx->iter) {
		ctx->iter = slist_iter_before_head(ctx->partial_files);
		g_assert(NULL == ctx->partial_tb);
		ctx->partial_tb = st_create();
	}

	if (!share_can_answer_partials())
		goto next;

	while (slist_iter_has_next(ctx->iter)) {
		const shared_file_t *sf = slist_iter_next(ctx->iter);

		shared_file_check(sf);
		g_assert(shared_file_is_partial(sf));

		st_insert_item(ctx->partial_tb, sf->name_canonic, sf);

		if (ctx->ticks++ >= ticks)
			return BGR_MORE;

		if (0 == (ctx->ticks & 0xf))
			bg_task_cancel_test(ctx->task);
	}

	/* Compact the search table */
	st_compact(ctx->partial_tb);
	ctx->ticks += 5;

next:
	slist_iter_free(&ctx->iter);

	bg_task_ticks_used(bt, ctx->ticks);
	return BGR_NEXT;
}

static bgret_t
recursive_scan_step_install_partials(struct bgtask *bt, void *data, int ticks)
{
	struct recursive_scan *ctx = data;

	recursive_scan_check(ctx);
	g_assert(ctx->partial_tb != NULL);

	(void) ticks;

	/*
	 * Install the new partial table, regardless of whether they allow queries
	 * to return partials: if they don't, the table is empty anyway.
	 */

	if (GNET_PROPERTY(share_debug) > 1) {
		int count = st_count(ctx->partial_tb);
		g_debug("SHARE installing new partial table (%d item%s)",
			count, plural(count));
	}

	SHARED_LIBFILE_LOCK;

	st_free(&shared_libfile.partial_table);
	shared_libfile.partial_table = ctx->partial_tb;
	ctx->partial_tb = NULL;

	SHARED_LIBFILE_UNLOCK;

	bg_task_ticks_used(bt, 0);
	return BGR_NEXT;
}

static void *
recursive_prepare_qrp(void *data)
{
	struct recursive_scan *ctx = data;

	recursive_scan_check(ctx);

	ctx->start_time = tm_time_exact();
	gnet_prop_set_timestamp_val(PROP_QRP_INDEXING_STARTED, ctx->start_time);

	return NULL;
}

static bgret_t
recursive_scan_step_prepare_qrp(struct bgtask *bt, void *data, int ticks)
{
	struct recursive_scan *ctx = data;

	recursive_scan_check(ctx);
	(void) ticks;

	/*
	 * Funnel back all property changes to the main thread.
	 */

	teq_safe_rpc(THREAD_MAIN, recursive_prepare_qrp, ctx);

	qrp_prepare_computation();
	ctx->idx = 0;

	bg_task_ticks_used(bt, 0);
	return BGR_NEXT;
}

static bgret_t
recursive_scan_step_update_qrp_lib(struct bgtask *bt, void *data, int ticks)
{
	struct recursive_scan *ctx = data;
	shared_file_t *sf;

	recursive_scan_check(ctx);

	ctx->ticks = 0;

	/*
	 * If we're coming from a rescan, then we have already loaded the ftable[]
	 * copy in the context.
	 *
	 * Otherwise, the ctx->ftable array will be null and we need to load
	 * a copy of the shared files, atomically.
	 */

	if (0 == ctx->idx && NULL == ctx->ftable)
		recursive_scan_load_ftable(ctx);

	for (;;) {
		SHARED_LIBFILE_LOCK;

		if (UNSIGNED(ctx->idx) >= shared_libfile.files_scanned) {
			SHARED_LIBFILE_UNLOCK;
			break;
		}
		sf = shared_libfile.sorted_file_table[ctx->idx];
		if (sf != NULL)
			sf = shared_file_ref(sf);

		SHARED_LIBFILE_UNLOCK;

		if (NULL == sf)
			continue;

		qrp_add_file(sf, ctx->words);
		shared_file_unref(&sf);

		if (ctx->ticks++ >= ticks)
			return BGR_MORE;

		if (0 == (ctx->ticks & 0xf))
			bg_task_cancel_test(ctx->task);

		ctx->idx++;
	}

	bg_task_ticks_used(bt, ctx->ticks);
	return BGR_NEXT;
}

static bgret_t
recursive_scan_step_update_qrp_partial(struct bgtask *bt, void *data, int ticks)
{
	struct recursive_scan *ctx = data;
	shared_file_t *sf;
	uint64 scanned = files_scanned();

	ctx->ticks = 0;

	while (NULL != (sf = slist_shift(ctx->partial_files))) {
		shared_file_check(sf);

		/*
		 * Assign a unique file index to each partial file, but don't flag
		 * the partial file with SHARE_F_INDEXED as we don't map the index
		 * to the partial file (we only allow retrieval of partials by SHA1).
		 *
		 * The file index is required to send proper information in query hits
		 * when inserting partial files.
		 */

		sf->file_index = scanned + (hset_count(partial_files) -
			slist_length(ctx->partial_files));

		qrp_add_file(sf, ctx->words);
		shared_file_unref(&sf);

		if (ctx->ticks++ >= ticks)
			return BGR_MORE;

		if (0 == (ctx->ticks & 0xf))
			bg_task_cancel_test(ctx->task);
	}

	bg_task_ticks_used(bt, ctx->ticks);
	return BGR_NEXT;
}

static void *
recursive_scan_finalize(void *arg)
{
	struct recursive_scan *ctx = arg;
	time_delta_t elapsed;

	recursive_scan_check(ctx);

	elapsed = delta_time(tm_time(), ctx->start_time);
	elapsed = MAX(0, elapsed);

	gnet_prop_set_guint32_val(PROP_QRP_INDEXING_DURATION, elapsed);

	qrp_finalize_computation(ctx->words);
	ctx->words = NULL;		/* Gave pointer, QRP computation will free it */

	return NULL;
}

static bgret_t
recursive_scan_step_finalize(struct bgtask *bt, void *data, int ticks)
{
	struct recursive_scan *ctx = data;

	recursive_scan_check(ctx);
	(void) bt;
	(void) ticks;

	/*
	 * Cannot change a property that can trigger a GTK update from another
	 * thread, we need to funnel this back to the main thread.
	 *
	 * Also, we want to run the QRP computation background task from the
	 * main thread, not from the library thread.
	 */

	teq_safe_rpc(THREAD_MAIN, recursive_scan_finalize, ctx);

	return BGR_DONE;
}

/**
 * Create a new background task for library rescan (+ QRP rebuilding).
 *
 * @param bs		the scheduler to which task should be inserted into
 *
 * @return a new background task.
 */
static struct bgtask *
share_rescan_create_task(bgsched_t *bs)
{
	static const bgstep_cb_t steps[] = {
		recursive_scan_step_setup,
		recursive_scan_step_compute,
		recursive_scan_step_compute_done,
		recursive_scan_step_build_search_table,
		recursive_scan_step_build_file_table,
		recursive_scan_step_build_basenames,
		recursive_scan_step_update_scan_timing,
		recursive_scan_step_build_sorted_table,
		recursive_scan_step_install_shared,
		recursive_scan_step_request_sha1,

		/*
		 * Remains steps identical to the ones listed in
		 * share_update_qrp_create_task().
		 */

		recursive_scan_step_load_partials,
		recursive_scan_step_build_partial_table,
		recursive_scan_step_install_partials,
		recursive_scan_step_prepare_qrp,
		recursive_scan_step_update_qrp_lib,
		recursive_scan_step_update_qrp_partial,
		recursive_scan_step_finalize,
	};
	struct recursive_scan *ctx;

	ctx = recursive_scan_new(shared_dirs, tm_time());

	return ctx->task = bg_task_create(bs, "recursive scan",
				steps, G_N_ELEMENTS(steps),
				ctx, recursive_scan_context_free,
				recursive_scan_done, NULL);
}

/**
 * Create a new background task for QRP rebuilding.
 *
 * @param bs		the scheduler to which task should be inserted into
 *
 * @return a new background task.
 */
static struct bgtask *
share_update_qrp_create_task(bgsched_t *bs)
{
	static const bgstep_cb_t steps[] = {
		recursive_scan_step_qrp_setup,
		recursive_scan_step_load_partials,
		recursive_scan_step_build_partial_table,
		recursive_scan_step_install_partials,
		recursive_scan_step_prepare_qrp,
		recursive_scan_step_update_qrp_lib,
		recursive_scan_step_update_qrp_partial,
		recursive_scan_step_finalize,
	};
	struct recursive_scan *ctx;

	ctx = recursive_scan_new(NULL, tm_time());

	return ctx->task = bg_task_create(bs, "QRP update",
				steps, G_N_ELEMENTS(steps),
				ctx, recursive_scan_context_free,
				recursive_scan_done, NULL);
}

/*
 * The "share_thread_lib_xxx" routine is the implementation, within the
 * "library" thread, of the corresponding API invoked from the "main" thread.
 *
 * These are handled as TEQ events, and are therefore delivered to the
 * thread in the same order as they were issued.
 */

/**
 * Start a library scan.
 */
static void
share_thread_lib_rescan(void *unused_arg)
{
	struct share_thread_vars *v = &share_thread_vars;

	(void) unused_arg;

	spinlock(&v->lock);

	if (v->task != NULL) {
		bg_task_cancel(v->task);
		v->task = NULL;
	}

	v->qrp_rebuild = FALSE;		/* since rescan takes care of it */
	v->task = share_rescan_create_task(v->sched);

	spinunlock(&v->lock);
}

/**
 * Request a QRP rebuild.
 */
static void
share_thread_lib_qrp_rebuild(void *unused_arg)
{
	struct share_thread_vars *v = &share_thread_vars;
	bool pending;

	(void) unused_arg;

	spinlock(&v->lock);

	if (v->task != NULL) {
		v->qrp_rebuild = TRUE;		/* record for later */
	} else {
		v->task = share_update_qrp_create_task(v->sched);
		v->qrp_rebuild = FALSE;
	}

	pending = v->qrp_rebuild;
	spinunlock(&v->lock);

	if (GNET_PROPERTY(share_debug) > 1) {
		g_debug("SHARE background QRP recomputation %s",
			pending ? "recorded" : "started");
	}
}

/*
 * The "share_lib_xxx" routine constitute the API from the "main" thread to the
 * "library" thread.
 */

/**
 * Start a library scan.
 */
static void
share_lib_rescan(void)
{
	teq_post(share_thread_id, share_thread_lib_rescan, NULL);
}

/**
 * Request a QRP rebuild.
 *
 * This will update the QRP table, including both our shared library and our
 * partials.
 */
static void
share_lib_qrp_rebuild(void)
{
	teq_post(share_thread_id, share_thread_lib_qrp_rebuild, NULL);

	if (GNET_PROPERTY(share_debug) > 1) {
		g_debug("SHARE requested background QRP recomputation (%s)",
			share_can_answer_partials() ?
				"with partial files" : "library only");
	}
}

/**
 * Is there work pending for the library thread, or is thread terminated?
 */
static bool
share_thread_has_work(void *unused_arg)
{
	struct share_thread_vars *v = &share_thread_vars;
	(void) unused_arg;

	return atomic_bool_get(&v->exiting) || v->task != NULL || v->qrp_rebuild;
}

/**
 * Signal handler to terminate the library thread.
 */
static void
share_thread_terminate(int sig)
{
	struct share_thread_vars *v = &share_thread_vars;

	g_assert(TSIG_TERM == sig);

	if (GNET_PROPERTY(share_debug))
		g_debug("terminating library thread");

	atomic_bool_set(&v->exiting, TRUE);
	spinlock(&v->lock);
	if (v->task != NULL) {
		bg_task_cancel(v->task);
		v->task = NULL;
	}
	spinunlock(&v->lock);
}

/**
 * Library thread main loop.
 */
static void *
share_thread_main(void *arg)
{
	struct share_thread_vars *v = &share_thread_vars;
	barrier_t *b = arg;

	thread_set_name("library");
	teq_create();				/* Queue to receive TEQ events */
	thread_signal(TSIG_TERM, share_thread_terminate);
	v->sched = bg_sched_create("library", 1000000 /* 1 s */);

	barrier_wait(b);			/* Thread has initialized */
	barrier_free_null(&b);

	if (GNET_PROPERTY(share_debug))
		g_debug("library thread started");

	/*
	 * Process work until we're told to exit.
	 */

	while (!atomic_bool_get(&v->exiting)) {
		struct bgtask *bt;
		bool qrp_rebuild;

		if (GNET_PROPERTY(share_debug))
			g_debug("library thread sleeping");

		teq_wait(share_thread_has_work, NULL);

		if (atomic_bool_get(&v->exiting))
			break;						/* Terminated by signal */

		if (GNET_PROPERTY(share_debug))
			g_debug("library thread awoken");

		spinlock(&v->lock);
		bt = v->task;					/* The task run */
		spinunlock(&v->lock);

		g_assert(bt != NULL);

		while (0 != bg_sched_run(v->sched))
			thread_check_suspended();

		/*
		 * QRP table rebuilds can have been recorded whilst we were processing
		 * the previous task.  If one is present, create the task, which will
		 * make share_thread_has_work() to return TRUE.
		 */

		spinlock(&v->lock);
		if (v->task == bt)
			v->task = NULL;				/* Finished running previous task */
		qrp_rebuild = v->qrp_rebuild;
		spinunlock(&v->lock);

		if (qrp_rebuild)
			share_thread_lib_qrp_rebuild(NULL);
	}

	bg_sched_destroy_null(&v->sched);

	g_debug("library thread exiting");
	return NULL;
}

/**
 * Create a new library thread.
 *
 * This routine does not return until the library thread has been
 * correctly initialized, so that the caller can immediately start to
 * send TEQ events to the thread.
 *
 * @return thread ID, -1 on error.
 */
static int
share_thread_create(void)
{
	barrier_t *b;
	int r;

	b = barrier_new(2);

	/*
	 * The library thread is created as a detached thread because we
	 * do not expect any result from it.
	 *
	 * It is created as non-cancelable: to end it, we send it a TSIG_TERM.
	 */

	r = thread_create(share_thread_main, barrier_refcnt_inc(b),
			THREAD_F_DETACH | THREAD_F_NO_CANCEL | THREAD_F_NO_POOL,
			THREAD_STACK_MIN);

	if (-1 == r)
		s_error("%s(): cannot create library thread: %m", G_STRFUNC);

	barrier_wait(b);		/* Wait for thread to initialize */
	barrier_free_null(&b);

	return r;
}

/**
 * Perform scanning of the shared directories to build up the list of
 * shared files.
 */
void
share_scan(void)
{
	share_lib_rescan();
}

/**
 * Hash table iterator callback to free the value.
 */
static void
special_free_kv(const void *unused_key, void *val, void *unused_udata)
{
	shared_file_t *sf = val;

	(void) unused_key;
	(void) unused_udata;

	g_assert(SHARE_F_SPECIAL & sf->flags);
	shared_file_unref(&sf);
}

/**
 * Get rid of the special file descriptions, if any.
 */
static void
share_special_close(void)
{
	htable_foreach(special_names, special_free_kv, NULL);
	htable_free_null(&special_names);
}

/**
 * Shutdown cleanup.
 */
G_GNUC_COLD void
share_close(void)
{
	if (THREAD_MAIN != share_thread_id)
		thread_kill(share_thread_id, TSIG_TERM);

	/*
	 * This call must happen after node_close() to ensure the UDP TX scheduler
	 * has been released and that no messages there could invoked callbacks
	 * referring to OOB data that oob_close() is going to free up.
	 */

	share_special_close();
	free_extensions();
	pslist_foreach(shared_libfile.shared_files, shared_file_detach, NULL);
	share_free();
	shared_dirs_free();
	huge_close();
	qrp_close();
	oob_proxy_close();
	oob_close();			/* References hits, so needs ``sha1_to_share'' */
	qhit_close();
	st_free(&shared_libfile.partial_table);
	htable_free_null(&share_media_types);
	hset_free_null(&partial_files);
	hikset_free_null(&sha1_to_share);
	cq_cancel(&share_qrp_rebuild_ev);
}

/*
 * SHA1 digest processing
 */

/**
 * Set the SHA1 hash of a given shared_file. Take care of updating the
 * sha1_to_share structure. This function is called from inside the bowels of
 * huge.c when it knows what the hash associated to a file is.
 */
void
shared_file_set_sha1(shared_file_t *sf, const struct sha1 *sha1)
{
	shared_file_check(sf);
	g_assert(!shared_file_is_partial(sf));	/* Cannot be a partial file */

	sf->flags &= ~(SHARE_F_RECOMPUTING | SHARE_F_HAS_DIGEST);
	sf->flags |= sha1 ? SHARE_F_HAS_DIGEST : 0;

	if (sf->sha1 != NULL) {
		shared_file_t *current;

		current = hikset_lookup(sha1_to_share, sf->sha1);
		if (current) {
			shared_file_check(current);
			g_assert(SHARE_F_INDEXED & current->flags);

			if (sf == current) {
				hikset_remove(sha1_to_share, sf->sha1);
			}
		}
	}

	atom_sha1_change(&sf->sha1, sha1);

	/*
	 * If the file is no longer in the index table, it must not be
	 * put into the tree again. This might happen if a SHA-1 calculation
	 * from a previous rescan finishes after newly initiated rescan.
	 */

	if ((SHARE_F_INDEXED & sf->flags) && sf->sha1 != NULL) {
		shared_file_t *current;

		current = hikset_lookup(sha1_to_share, sf->sha1);
		if (current) {
			shared_file_check(current);
			g_assert(SHARE_F_INDEXED & current->flags);
			
			/*
			 * There can be multiple shared files with the same SHA-1.
			 * Only the first found is inserted into the tree.
			 */
			if (GNET_PROPERTY(share_debug) > 0) {
				g_debug("\"%s\" is a duplicate of \"%s\"",
					shared_file_path(sf),
					shared_file_path(current));
			}
		} else {
			/*
			 * New SHA-1 known for this file entry.
			 * Record in the set of shared SHA-1s and publish to the DHT.
			 */
		
			hikset_insert_key(sha1_to_share, &sf->sha1);

			/*
			 * Could be called from the "library" thread during scanning of
			 * the shared file.  Since publisher_add() will access an SDBM
			 * database via the DBMW layer, and that is not thread-safe yet,
			 * funnel back the call to the main thread.
			 *		--RAM, 2013-11-05
			 *
			 * We need a "safe" post because the publishing event can do
			 * heavy work and we could re-enter SDBM or the DBMW layer
			 * accidentally during the interruption, creating nasty effects
			 * if we, for instance, access a hash table being resized by an
			 * earlier call on the stack.
			 *		--RAM, 2014-01-02
			 */

			teq_safe_post(THREAD_MAIN, publisher_add_event,
				deconstify_pointer(sf->sha1));
		}
	}
}

void
shared_file_set_tth(shared_file_t *sf, const struct tth *tth)
{
	shared_file_check(sf);

	g_assert(!shared_file_is_partial(sf));	/* Cannot be a partial file */

	atom_tth_change(&sf->tth, tth);
}

void
shared_file_set_modification_time(shared_file_t *sf, time_t mtime)
{
	shared_file_check(sf);
	sf->mtime = mtime;
}

/**
 * Predicate returning TRUE if the SHA1 hash is available for a given
 * shared_file, FALSE otherwise.
 *
 * Use sha1_hash_is_uptodate() to check for availability and accurateness.
 */
bool
sha1_hash_available(const shared_file_t *sf)
{
	shared_file_check(sf);
	return SHARE_F_HAS_DIGEST ==
		(sf->flags & (SHARE_F_HAS_DIGEST | SHARE_F_RECOMPUTING));
}

/**
 * Predicate returning TRUE if the SHA1 hash is available AND is up to date
 * for the shared file.
 *
 * NB: if the file is found to have changed, the background computation of
 * the SHA1 is requested.
 */
bool
sha1_hash_is_uptodate(shared_file_t *sf)
{
	filestat_t buf;

	shared_file_check(sf);

	if (!(sf->flags & SHARE_F_HAS_DIGEST))
		return FALSE;

	if (sf->flags & SHARE_F_RECOMPUTING)
		return FALSE;

	/*
	 * If there is a non-NULL `fi' entry, then this is a partially
	 * downloaded file that we are sharing.  Don't try to update its
	 * SHA1 by recomputing it!
	 *
	 * If it's a partial file, don't bother checking whether it exists.
	 * (if gone, we won't be able to serve it, that's all).  But partial
	 * files we serve MUST have known SHA1.
	 */

	if (shared_file_is_partial(sf)) {
		g_assert(sf->fi->sha1 != NULL);
		return TRUE;
	}

	if (-1 == stat(sf->file_path, &buf)) {
		g_warning("can't stat shared file #%d \"%s\": %m",
			sf->file_index, sf->file_path);
		shared_file_set_sha1(sf, NULL);
		return FALSE;
	}

	if (too_big_for_gnutella(buf.st_size)) {
		g_warning("file is too big to be shared: \"%s\"", sf->file_path);
		shared_file_set_sha1(sf, NULL);
		return FALSE;
	}

	/*
	 * If file was modified since the last time we computed the SHA1,
	 * recompute it and tell them that the SHA1 we have might not be
	 * accurate.
	 */

	if (
			sf->mtime != buf.st_mtime ||
			sf->file_size + (fileoffset_t) 0 != buf.st_size + (filesize_t) 0
	) {
		g_warning("shared file #%d \"%s\" changed, recomputing SHA1",
			sf->file_index, sf->file_path);
		sf->flags |= SHARE_F_RECOMPUTING;
		sf->mtime = buf.st_mtime;
		sf->file_size = buf.st_size;
		request_sha1(sf);
		return FALSE;
	}

	return TRUE;
}

/**
 * Whether file is finished (i.e. either shared from the library or seeded).
 */
bool
shared_file_is_finished(const shared_file_t *sf)
{
	shared_file_check(sf);
	return NULL == sf->fi || 0 != (sf->fi->flags & FI_F_SEEDING);
}

bool
shared_file_is_partial(const shared_file_t *sf)
{
	shared_file_check(sf);
	return NULL != sf->fi;
}

bool
shared_file_is_shareable(const shared_file_t *sf)
{
	shared_file_check(sf);

	/*
	 * A zeroed file_index indicates we called shared_file_deindex(),
	 * most probably through shared_file_remove().
	 *
	 * We don't want to include this file in query hits even though the
	 * file entry happens to be still listed in search bins (for instance
	 * because it was removed dynamically as we discovered it was spam).
	 *
	 * Thanks to Dmitry Butskoy for investigating this corner case.
	 *		--RAM, 2011-11-30
	 */

	return sf->file_index != 0;
}

filesize_t
shared_file_size(const shared_file_t *sf)
{
	shared_file_check(sf);
	return sf->file_size;
}

/**
 * Get the file index in the library for the given shared file.
 *
 * @return the file index, or 0 if the shared file is no longer part of the
 * library (a concurrent library rescan invalidated that file for now).
 */
uint32
shared_file_index(const shared_file_t *sf)
{
	uint32 idx;

	shared_file_check(sf);

	idx = sf->file_index;

	/*
	 * Watch out for concurrent library rescan de-indexing a file that would
	 * be, for instance, part of a query hit that we're constructing.
	 */

	if G_UNLIKELY(0 == idx) {
		/*
		 * File was de-indexed, meaning the reference we have on it is no
		 * longer attached to the library.  If the file has a SHA1, we may
		 * still be able to locate a suitable file index for that SHA1.
		 */

		if (sf->sha1 != NULL) {
			shared_file_t *sfx;

			SHARED_LIBFILE_LOCK;
			sfx = hikset_lookup(sha1_to_share, sf->sha1);
			if (sfx != NULL) {
				idx = sfx->file_index;
				g_assert(sfx->file_index != 0);
			}
			SHARED_LIBFILE_UNLOCK;
		}
	}

	g_assert(PARTIAL_FILE != idx || NULL != sf->fi);

	return idx;
}

const struct sha1 *
shared_file_sha1(const shared_file_t *sf)
{
	shared_file_check(sf);
	return sf->sha1;
}

const struct tth *
shared_file_tth(const shared_file_t *sf)
{
	shared_file_check(sf);
	return sf->tth;
}

const char *
shared_file_name_nfc(const shared_file_t *sf)
{
	shared_file_check(sf);
	return sf->name_nfc;
}

const char *
shared_file_name_canonic(const shared_file_t *sf)
{
	shared_file_check(sf);
	return sf->name_canonic;
}

size_t
shared_file_name_nfc_len(const shared_file_t *sf)
{
	shared_file_check(sf);
	return sf->name_nfc_len;
}

size_t
shared_file_name_canonic_len(const shared_file_t *sf)
{
	shared_file_check(sf);
	return sf->name_canonic_len;
}

/**
 * Returns the relative path of the shared files unless there was none
 * or exposing relative paths is disabled.
 *
 * @return A string or NULL.
 */
const char *
shared_file_relative_path(const shared_file_t *sf)
{
	shared_file_check(sf);
	return GNET_PROPERTY(search_results_expose_relative_paths)
			? sf->relative_path
			: NULL;
}

/**
 * Get the pathname of a shared file.
 *
 * @param sf an initialized shared file.
 * @return	the full pathname of the shared file. The returned pointer is
 *			a string atom.
 */
const char *
shared_file_path(const shared_file_t *sf)
{
	shared_file_check(sf);
	return sf->file_path;
}

/**
 * @return the last modification time of the shared file.
 */
time_t
shared_file_modification_time(const shared_file_t *sf)
{
	shared_file_check(sf);

	/*
	 * For partial files, we need to query the fileinfo as the value in
	 * the shared_file is the one copied at the time we create the
	 * structure from the partial file. It is not updated regularily.
	 */

	return NULL == sf->fi ? sf->mtime : sf->fi->modified;
}

/**
 * @return the creation time of the shared file.
 */
time_t
shared_file_creation_time(const shared_file_t *sf)
{
	shared_file_check(sf);
	return sf->ctime;
}

/**
 * @return available bytes (same as filesize, unless file is partial).
 */
filesize_t
shared_file_available(const shared_file_t *sf)
{
	shared_file_check(sf);

	/*
	 * For partial files, we need to query the fileinfo as the value in
	 * the shared_file is the one copied at the time we create the
	 * structure from the partial file. It is not updated regularily.
	 */

	return NULL == sf->fi
		? sf->file_size
		: (sf->fi->buffered + sf->fi->done);
}

bool
shared_file_indexed(const shared_file_t *sf)
{
	shared_file_check(sf);
	return 0 != (SHARE_F_INDEXED & sf->flags);
}

uint32
shared_file_flags(const shared_file_t *sf)
{
	shared_file_check(sf);
	return sf->flags;
}

fileinfo_t *
shared_file_fileinfo(const shared_file_t *sf)
{
	shared_file_check(sf);
	return sf->fi;
}

const char *
shared_file_mime_type(const shared_file_t *sf)
{
	shared_file_check(sf);
	return mime_type_to_string(sf->mime_type);
}

void
shared_file_remove(shared_file_t *sf)
{
	shared_file_check(sf);

	shared_file_deindex(sf);

	if G_UNLIKELY(0 == sf->refcnt) {
		g_carp("%s(): called on unreferenced file \"%s\"",
			G_STRFUNC, sf->file_path);
		shared_file_free(&sf);
	}
}

void
shared_file_set_path(shared_file_t *sf, const char *pathname)
{
	shared_file_check(sf);
	atom_str_change(&sf->file_path, pathname);
}

void
shared_file_from_fileinfo(fileinfo_t *fi)
{
	shared_file_t *sf;

	file_info_check(fi);
	g_assert(NULL == fi->sf);

	sf = shared_file_alloc();
	sf->flags = SHARE_F_HAS_DIGEST;
	sf->mtime = fi->last_flush;
	sf->ctime = fi->created;
	sf->sha1 = atom_sha1_get(fi->sha1);

	/* FIXME: DOWNLOAD_SIZE:
	 * Do we need to add anything here now that fileinfos can have an
	 *  unknown length? --- Emile
	 */

	sf->file_size = fi->size;
	sf->file_index = PARTIAL_FILE;	/* Until inserted in partial search table */

	/*
	 * Determine a proper human-readable name for the file.
	 * If it is an URN, look through the aliases.
	 */

	if (shared_file_set_names(sf, file_info_readable_filename(fi))) {
		shared_file_free(&sf);
		return;
	}

	sf->mime_type = mime_type_from_filename(sf->name_nfc);
	sf->file_path = atom_str_get(fi->pathname);
	sf->flags |= SHARE_F_FILEINFO;

	sf->fi = fi;		/* Signals it's a partially downloaded file */
	fi->sf = shared_file_ref(sf);
}

/**
 * Get shared file identified by its SHA1.
 *
 * The returned file is reference-counted if not a special value.
 *
 * @return the shared_file if we share a complete file bearing the given SHA1,
 * or NULL if we don't share a complete file, or SHARE_REBUILDING if the
 * set of shared file is being rebuilt.
 */
static shared_file_t *
shared_file_complete_by_sha1(const struct sha1 *sha1)
{
	shared_file_t *sf;

	if (sha1_to_share == NULL)			/* Not even begun share_scan() yet */
		return SHARE_REBUILDING;

	SHARED_LIBFILE_LOCK;

	sf = hikset_lookup(sha1_to_share, sha1);
	if (sf != NULL)
		shared_file_ref(sf);

	SHARED_LIBFILE_UNLOCK;

	if (!sf || !sha1_hash_available(sf)) {
		/*
		 * If we're rebuilding the library, we might not have parsed the
		 * file yet, so it's possible we have this URN but we don't know
		 * it yet.	--RAM, 12/10/2002.
		 */

		return atomic_bool_get(&share_rebuilding) ? SHARE_REBUILDING : NULL;
	}

	return sf;
}

/**
 * Take a given binary SHA1 digest, and return the corresponding
 * shared_file if we have it.
 *
 * The returned file is reference-counted hence caller needs to call
 * shared_file_unref().
 *
 * @attention
 * NB: if the returned "shared_file" structure holds a non-NULL `fi',
 * then it means it is a partially shared file.
 *
 * @returns NULL if we don't share a complete file, or SHARE_REBUILDING if the
 * set of shared file is being rebuilt.
 */
shared_file_t *
shared_file_by_sha1(const struct sha1 *sha1)
{
	shared_file_t *f;

	f = shared_file_complete_by_sha1(sha1);		/* Ref-counted now */

	/*
	 * If we don't share this file, or if we're rebuilding, and provided
	 * PFSP-server is enabled, look whether we don't have a partially
	 * downloaded file with this SHA1.
	 */

	if (f == NULL || f == SHARE_REBUILDING) {
		if (GNET_PROPERTY(pfsp_server) || GNET_PROPERTY(pfsp_rare_server)) {
			shared_file_t *sf = file_info_shared_sha1(sha1);
			if (sf != NULL) {
				if (GNET_PROPERTY(pfsp_rare_server)) {
					if (download_sha1_is_rare(sha1)) {
						f = shared_file_ref(sf);
					}
				} else {
					f = shared_file_ref(sf);
				}
			}
		}
	}
	if (f && SHARE_REBUILDING != f) {
		shared_file_check(f);
	}
	return f;
}

/**
 * Fill the supplied shared_file vector, holding sfcount entries, with the
 * most recent shared files we have in the library matching the supplied
 * media_mask (if non-zero) and which are less than SHARE_RECENT_THRESH
 * seconds old.
 *
 * @attention
 * Entries filled in the sfvec[] array are ref-counted and the caller is
 * responsible for calling shared_file_unref() on each entry after using it.
 *
 * @param sfvec			the vector to fill in
 * @param sfcount		the size of the vector
 * @param media_mask	media-type filtering to apply
 * @param size_restrict	whether to apply filesize restrictions
 * @param minsize		if applicable, the minimal size
 * @param maxsize		if applicable, the maximum size
 *
 * @return the amount of entries filled in the vector.
 */
size_t
share_fill_newest(shared_file_t **sfvec, size_t sfcount,
	unsigned media_mask,
	bool size_restrict, filesize_t minsize, filesize_t maxsize)
{
	int i;
	size_t j;

	g_assert(sfvec != NULL);
	g_assert(size_is_positive(sfcount));

	SHARED_LIBFILE_LOCK;

	if (NULL == shared_libfile.file_table) {
		SHARED_LIBFILE_UNLOCK;
		return 0;
	}

	g_assert(shared_libfile.files_scanned != 0);

	for (
		i = shared_libfile.files_scanned - 1, j = 0;
		i >= 0 && j < sfcount;
		i--
	) {
		shared_file_t *sf = shared_libfile.file_table[i];

		if (sf != NULL) {
			shared_file_check(sf);

			/* file_table[] is sorted by increasing mtime */

			if (delta_time(tm_time(), sf->mtime) > SHARE_RECENT_THRESH)
				break;		/* Deeper files will be older */

			if (media_mask != 0 && !shared_file_has_media_type(sf, media_mask))
				continue;

			if (size_restrict) {
				filesize_t size = shared_file_size(sf);
				if (size < minsize || size > maxsize)
					continue;
			}

			sfvec[j++] = shared_file_ref(sf);
		}
	}

	SHARED_LIBFILE_UNLOCK;

	return j;
}

/**
 * Is shared file belonging to the media types indicated by mask?
 */
bool
shared_file_has_media_type(const shared_file_t *sf, unsigned mask)
{
	unsigned type;

	shared_file_check(sf);

	type = pointer_to_uint(
		htable_lookup(share_media_types, int_to_pointer(sf->mime_type)));

	return 0 != (type & mask);
}

/**
 * Convenience routine: compute media type mask for a file name, corresponding
 * to the bits in the media type filter that must be set to return this type
 * of file.
 *
 * @return media mask associated to filename, 0 meaning we don't recognize
 * this type of file.
 */
unsigned
share_filename_media_mask(const char *filename)
{
	enum mime_type mime;
	const void *v;

	mime = mime_type_from_filename(filename);
	v = htable_lookup(share_media_types, int_to_pointer(mime));

	return pointer_to_uint(v);
}

/**
 * Get accessor for ``kbytes_scanned''
 */
uint64
shared_kbytes_scanned(void)
{
	return bytes_scanned() / 1024;
}

/**
 * Get accessor for ``files_scanned''
 */
uint64
shared_files_scanned(void)
{
	return files_scanned();
}

/**
 * Request asynchronous partial file table (for pattern matching) and QRP
 * table rebuild if necessary.
 */
static void
share_qrp_rebuild_if_needed(void)
{
	if (share_can_answer_partials())
		share_lib_qrp_rebuild();
}

/**
 * Records partial file entry.
 */
void
share_add_partial(const shared_file_t *sf)
{
	g_assert(shared_file_is_partial(sf));

	if (hset_contains(partial_files, sf))
		return;

	hset_insert(partial_files, sf);

	/*
	 * We added a new partial file, we need to rebuild the QRP table.
	 * Do that asynchronously in case we're called frequently from a loop,
	 * for instance at startup or when many new files are downloaded.
	 */

	share_qrp_rebuild_if_needed();

	if (GNET_PROPERTY(share_debug) > 1)
		g_debug("SHARE added partial file \"%s\"", shared_file_path(sf));
}

/**
 * Removes partial file entry.
 */
void
share_remove_partial(const shared_file_t *sf)
{
	g_assert(shared_file_is_partial(sf));

	if (!hset_remove(partial_files, sf))
		return;

	/*
	 * We removed a partial file, we need to rebuild the QRP table.
	 */

	share_qrp_rebuild_if_needed();

	if (GNET_PROPERTY(share_debug) > 1)
		g_debug("SHARE removed partial file \"%s\"", shared_file_path(sf));
}

/**
 * Whenever support for partial file sharing or partial result answering
 * changes, rebuild the QRP and matching tables, asynchronously.
 */
void
share_update_matching_information(void)
{
	share_lib_qrp_rebuild();
}

/**
 * Initialization of the sharing library.
 */
G_GNUC_COLD void
share_init(void)
{
	size_t i;

	huge_init();
	qrp_init();
	qhit_init();
	oob_init();
	oob_proxy_init();
	share_special_init();

	/*
	 * We allocate an empty search_table, which will be de-allocated when we
	 * call share_scan().  Why do we do this?  Because it ensures the table
	 * is correctly setup empty, until we do call share_scan() for the first
	 * time (the call is delayed until the GUI is up).
	 *
	 * Since we will start processing network packets, we will have a race
	 * condition window if we get a Query message before having started
	 * the share_scan().  Creating the table right now prevents adding an
	 * extra test at the top of st_search().
	 *		--RAM, 15/08/2002.
	 */

	shared_libfile.search_table = st_create();

	/*
	 * Intialize partial file querying structures (so that queries can
	 * be applied to partial files).
	 */

	partial_files = hset_create(HASH_KEY_SELF, 0);
	hset_thread_safe(partial_files);

	shared_libfile.partial_table = st_create();

	/*
	 * Create the hash table yielding the media type flags from a MIME type.
	 */

	share_media_types = htable_create(HASH_KEY_SELF, 0);

	for (i = 0; i < G_N_ELEMENTS(media_type_map); i++) {
		htable_insert(share_media_types,
			int_to_pointer(media_type_map[i].type),
			int_to_pointer(media_type_map[i].flags));
	}

	/*
	 * If we have at least 2 CPUs available, create a library thread.
	 * Otherwise, library scanning will be handled by the main thread.
	 */

	if (getcpucount() >= 2) {
		share_thread_id = share_thread_create();
	} else {
		share_thread_id = THREAD_MAIN;
		g_assert(THREAD_MAIN == thread_by_name("main"));
	}
}

/* vi: set ts=4 sw=4 cindent: */
