/*
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
 * @ingroup core
 * @file
 *
 * GGEP type-specific routines.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#ifndef _core_ggep_type_h_
#define _core_ggep_type_h_

#include "common.h"

#include "lib/host_addr.h"
#include "lib/sequence.h"
#include "if/core/search.h"

#include "ggep.h"

/**
 * Extraction interface return types.
 */

typedef enum ggept_status {
	GGEP_OK = 0,				/**< OK, extracted what was asked */
	GGEP_NOT_FOUND,				/**< OK, but did not find it */
	GGEP_INVALID,				/**< Error, found something invalid */
	GGEP_DUPLICATE,				/**< Error, duplicate extension */
	GGEP_BAD_SIZE				/**< Error, buffer not correctly sized */
} ggept_status_t;

/*
 * Flags for the GTKGV extension (version >= 1).
 */

#define GTKGV_F_CONT	(1U << 7)	/**< Continuation flag */
#define GTKGV_F_GIT		(1U << 0)	/**< Has git commit identifier */
#define GTKGV_F_DIRTY	(1U << 1)	/**< Had local changes at build time */
#define GTKGV_F_OS		(1U << 2)	/**< Has OS code */

#define GTKGV_MAX_LEN	37			/**< Maximum length of "GTKGV", + 1 NUL */

/*
 * Public interface.
 */

struct gnutella_host;

ggept_status_t ggept_h_sha1_extract(const extvec_t *, struct sha1 *);
ggept_status_t ggept_h_tth_extract(const extvec_t *, struct tth *);

/** Decompiled payload of "GTKGV1" (deprecated @0.97) */
struct ggep_gtkgv1 {
	uint8 major;
	uint8 minor;
	uint8 patch;
	uint8 revchar;
	uint32 release;
	uint32 build;
};

/** Decompiled payload of "GTKGV" */
struct ggep_gtkgv {
	uint8 version;		/**< Initial version: 0 */
	uint8 major;
	uint8 minor;
	uint8 patch;
	uint8 revchar;
	uint32 release;
	uint32 build;
	/* Introduced at version 1 */
	const char *osname;		/**< Operating system name (static string) */
	sha1_t commit;			/**< Commit version (may be partial) */
	uint8 commit_len;		/**< Amount of valid nybbles */
	unsigned dirty:1;
};

size_t ggept_gtkgv_build(void *buf, size_t len);

ggept_status_t ggept_gtkgv_extract(const extvec_t *, struct ggep_gtkgv *info);
ggept_status_t ggept_gtkgv_extract_data(const void *buf, size_t len,
	struct ggep_gtkgv *info);
ggept_status_t ggept_gtkgv1_extract(const extvec_t *, struct ggep_gtkgv1 *info);
ggept_status_t ggept_hname_extract(const extvec_t *, char *buf, int len);
ggept_status_t ggept_filesize_extract(const extvec_t *, uint64 *fs);
ggept_status_t ggept_uint32_extract(const extvec_t *exv, uint32 *val);
ggept_status_t ggept_du_extract(const extvec_t *, uint32 *uptime);
ggept_status_t ggept_ct_extract(const extvec_t *, time_t *stamp_ptr);
ggept_status_t ggept_gtkg_ipv6_extract(const extvec_t *, host_addr_t *addr);
ggept_status_t ggept_stamp_filesize_extract(const extvec_t *exv,
	time_t *stamp, uint64 *filesize);

ggept_status_t ggept_alt_extract(const extvec_t *,
	gnet_host_vec_t **hvec, enum net_type net);
ggept_status_t ggept_push_extract(const extvec_t *,
	gnet_host_vec_t **hvec, enum net_type net);
ggept_status_t ggept_utf8_string_extract(const extvec_t *, char *b, size_t l);

uint ggept_filesize_encode(uint64 filesize, char *data, size_t len);
uint ggept_stamp_filesize_encode(time_t s, uint64 fs, char *data, size_t len);
uint ggept_du_encode(uint32 uptime, char *data, size_t len);
uint ggept_ct_encode(time_t stamp, char *data, size_t len);
uint ggept_m_encode(uint32 mtype, char *data, size_t len);

ggept_status_t ggept_ipp_pack(ggep_stream_t *gs,
	const gnet_host_t *hvec, size_t hcnt,
	const gnet_host_t *evec, size_t ecnt,
	bool add_ipv6, bool no_ipv4);
ggept_status_t ggept_dhtipp_pack(ggep_stream_t *gs,
	const gnet_host_t *hvec, size_t hcnt,
	bool add_ipv6, bool no_ipv4);
ggept_status_t ggept_push_pack(ggep_stream_t *gs,
	const sequence_t *hseq, size_t max, unsigned flags);
ggept_status_t ggept_a_pack(ggep_stream_t *gs,
	const gnet_host_t *hvec, size_t hcnt);
ggept_status_t ggept_alt_pack(ggep_stream_t *gs,
	const gnet_host_t *hvec, size_t hcnt, unsigned flags);

#endif	/* _core_ggep_type_h_ */

/* vi: set ts=4 sw=4 cindent: */
