/*
 * Copyright (c) 2008, 2012 Raphael Manfredi
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
 * Debug level configuration for library files.
 *
 * @author Raphael Manfredi
 * @date 2008, 2012
 */

#ifndef _debug_h_
#define _debug_h_

#include "common.h"

extern uint32 common_dbg;		/**< Debug level for library files */
extern uint32 common_stats;		/**< Log level for library statistics */

void set_library_debug(uint32 level);
void set_library_stats(uint32 level);

/*
 * Data structure debugging.
 */

/**
 * Generic debugging configuration for data structures, which can be
 * statically initialized to debug a particular instance of a data structure.
 *
 * This is suitable for lists, trees, hash tables, etc...
 *
 * The data structure can use dbg_ds_log() calls to log debugging information,
 * conditionally guarded by dbg_ds_debugging() checks.  The latter call
 * compares the specified level and flags to the ones held in the structure to
 * determine whether one should actually perform logging.
 *
 * The logging routine automatically adds the prefix string, followed by
 * the type of data structure and a stringified representation of the object
 * being debugged.
 *
 * Data structures willing to be dynamically debuggable with this mechanism
 * should reserve an attribute in their structure (and a procedure to set
 * the variable from the outside):
 *
 *		const dbg_config_t *dbg;
 *
 * If NULL, then no debugging will occur, i.e. dbg_ds_debugging() will
 * never return TRUE.
 *
 * Although the attribute is declared "const" (i.e. the data structure is
 * not going to need to modify this object), the user may alter the value of
 * the level and flags dynamically, to adjust debugging levels and areas.
 *
 * All the stringification routines can be NULL, and a suitable generic
 * stringification will be used.  The prefix and type must not be NULL but
 * can be set to the empty string.
 *
 * The length-aware stringification routine is called when the length of
 * the key/value is known.  See dbg_ds_keystr() and dbg_ds_valstr(), which
 * are the entry points to generate to stringified keys and values in the
 * log messages.
 */
typedef struct dbg_config {
	const char *prefix;			/**< Debugging prefix to use */
	const char *type;			/**< Type of data structure */
	unsigned level;				/**< Debugging level */
	unsigned flags;				/**< Debugging flags */
	stringify_fn_t o2str;		/**< Stringification for object debugged */
	stringify_fn_t k2str;		/**< Stringification for keys */
	stringify_len_fn_t klen2str;/**< Alternate stringification for keys */
	stringify_fn_t v2str;		/**< Stringification for values */
	stringify_len_fn_t vlen2str;/**< Alternate stringification for values */
} dbg_config_t;

/**
 * Debugging flags for dbg_config, to select particular areas of the code.
 * (DSF = Data Structure Flags)
 *
 * Those are completely general and their usage depends on the data structure,
 * although of course the named categories should be used to segregate logs.
 */
#define DBG_DSF_INSERT		(1U << 0)	/**< Insertions */
#define DBG_DSF_UPDATE		(1U << 1)	/**< Updates */
#define DBG_DSF_DELETE		(1U << 2)	/**< Deletions */
#define DBG_DSF_ACCESS		(1U << 3)	/**< Accesses */
#define DBG_DSF_CACHING		(1U << 4)	/**< Caching */
#define DBG_DSF_STATS		(1U << 5)	/**< Statistics */
#define DBG_DSF_CONFIG		(1U << 6)	/**< Configuration */
#define DBG_DSF_DEBUGGING	(1U << 7)	/**< Debug plugging */
#define DBG_DSF_DESTROY		(1U << 8)	/**< Destruction of data structure */
#define DBG_DSF_ITERATOR	(1U << 9)	/**< Iterators */
#define DBG_DSF_USR1		(1U << 10)	/**< User-specific flag #1 */
#define DBG_DSF_USR2		(1U << 11)	/**< User-specific flag #2 */
#define DBG_DSF_USR3		(1U << 12)	/**< User-specific flag #3 */
#define DBG_DSF_LOG1		(1U << 13)	/**< Data-structure specific flag #1 */
#define DBG_DSF_LOG2		(1U << 14)	/**< Data-structure specific flag #2 */
#define DBG_DSF_LOG3		(1U << 15)	/**< Data-structure specific flag #3 */

#define DBG_DSF_ALL			0xffffffff	/**< All 32 debugging flags */

#define dbg_ds_debugging(dc, lvl, mask) \
	G_UNLIKELY((dc) != NULL && (dc)->level >= (lvl) && (dc)->flags & (mask))

const char *dbg_ds_name(const dbg_config_t *dc, const void *o);
const char *dbg_ds_keystr(const dbg_config_t *dc, const void *key, size_t len);
const char *dbg_ds_valstr(const dbg_config_t *dc, const void *val, size_t len);
void dbg_ds_log(const dbg_config_t *dc, const void *o,
	const char *fmt, ...) G_PRINTF(3, 4);
void dbg_ds_logv(const dbg_config_t *dc, const void *o,
	const char *fmt, va_list args);

#endif /* _debug_h_ */

/* vi: set ts=4 sw=4 cindent: */
