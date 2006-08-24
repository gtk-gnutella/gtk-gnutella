/*
 * $Id$
 *
 * Copyright (c) 2001-2003, Raphael Manfredi
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

#ifndef _core_gnutella_h_
#define _core_gnutella_h_

#include "if/core/gnutella.h"

/*
 * Constants
 */

#define GTA_MSGV_QRP_RESET				0x00
#define GTA_MSGV_QRP_PATCH				0x01

/*
 * Structures
 */

#if !defined(__GNUC__) && !defined(__attribute__)
#define __attribute__(p)
#endif

/* Messages structures */

struct gnutella_msg_init {
	struct gnutella_header header;
	/**< GGEP data may follow */
};

struct gnutella_init_response {
	guchar host_port[2];
	guchar host_ip[4];
	guchar files_count[4];
	guchar kbytes_count[4];
};

struct gnutella_msg_init_response {
	struct gnutella_header header;
	struct gnutella_init_response response;
	/**< GGEP data may follow */
};

struct gnutella_search {
	guchar speed[2];
	/**< query string follows */
};

struct gnutella_search_results {
	guchar num_recs;
	guchar host_port[2];
	guchar host_ip[4];
	guchar host_speed[4];
	/* record data follows */

	/* Last 16 bytes = client_id */
};

struct gnutella_msg_search {
	struct gnutella_header header;
	struct gnutella_search search;
};

struct gnutella_push_request {
	guchar guid[16];
	guchar file_id[4];
	guchar host_ip[4];
	guchar host_port[2];
};

struct gnutella_msg_push_request {
	struct gnutella_header header;
	struct gnutella_push_request request;
	/**< GGEP data may follow */
};

struct gnutella_bye {
	guchar code[2];
	/**< message string follows */
};

struct gnutella_qrp_reset {
	guchar variant;			/**< 0x00 */
	guchar table_length[4];	/**< little endian */
	guchar infinity;
};

struct gnutella_msg_qrp_reset {
	struct gnutella_header header;
	struct gnutella_qrp_reset data;
};

struct gnutella_qrp_patch {
	guchar variant;			/**< 0x01 */
	guchar seq_no;
	guchar seq_size;
	guchar compressor;
	guchar entry_bits;
};

struct gnutella_msg_qrp_patch {
	struct gnutella_header header;
	struct gnutella_qrp_patch data;
};

struct gnutella_vendor {
	guchar vendor[4];		/**< For example, "GTKG" */
	guchar selector_id[2];	/**< Message selector ID, little endian */
	guchar version[2];		/**< Message version number, little endian */
	/* payload follows */
};

struct gnutella_msg_vendor {
	struct gnutella_header header;
	struct gnutella_vendor data;
};

struct gnutella_msg_hsep_data {
	struct gnutella_header header;
	guchar triple[3 * sizeof(guint64)];
};

#endif /* _core_gnutella_h_ */

/* vi: set ts=4 sw=4 cindent: */
