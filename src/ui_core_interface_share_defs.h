/*
 * FILL_IN_EMILES_BLANKS
 *
 * Interface definition file.  One of the files that defines structures,
 * macros, etc. as part of the gui/core interface.
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

#ifndef _ui_core_interface_share_defs_h_
#define _ui_core_interface_share_defs_h_

#include "ui_core_interface_gnet_share_defs.h"
#include "ui_core_interface_common_defs.h"

/* A file extension we have to share */
struct extension {
	gchar *str;			/* Extension string (e.g. "html") */
	gint len;			/* Extension length (e.g. 4) */
};

typedef struct shared_file {
	gchar *file_path;		/* The full path of the file */
	const gchar *file_name;	/* Pointer within file_path at start of filename */
	guint32 file_index;		/* the files index within our local DB */
	guint32 file_size;		/* File size in Bytes */
	guint32 flags;			/* See below for definition */
	gint file_name_len;
	time_t mtime;			/* Last modification time, for SHA1 computation */
	gchar sha1_digest[SHA1_RAW_SIZE];	/* SHA1 digest, binary form */
	struct dl_file_info *fi;			/* PFSP-server: the holding fileinfo */
} shared_file_t;

/*
 * shared_file flags
 */

#define SHARE_F_HAS_DIGEST	0x00000001		/* Digest is set */
#define SHARE_F_RECOMPUTING	0x00000002		/* Digest being recomputed */

struct gnutella_search_results_out {
	guchar num_recs;
	guchar host_port[2];
	guchar host_ip[4];
	guchar host_speed[4];

	/* Last 16 bytes = client_id */
};


#define SHARE_REBUILDING	((struct shared_file *) 0x1)



#endif
