/*
 * Copyright (c) 2001-2004, Raphael Manfredi & Richard Eckart
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup gtk
 * @file
 *
 * Columns in the panes.
 *
 * @author Raphael Manfredi
 * @author Richard Eckart
 * @date 2001-2004
 */

#ifndef _gtk_columns_h_
#define _gtk_columns_h_

/**
 * Gnet table columns.
 */

enum c_gnet {
	c_gnet_host,
	c_gnet_loc,
	c_gnet_flags,
	c_gnet_user_agent,
	c_gnet_version,
	c_gnet_connected,
	c_gnet_uptime,
	c_gnet_info,
#define NODES_VISIBLE_COLUMNS ((guint) c_gnet_info + 1)
#ifdef USE_GTK2
	c_gnet_handle,
	c_gnet_fg,
#endif
	c_gnet_num
};

/**
 * Uploads table columns.
 */

enum {
    c_ul_filename,
    c_ul_host,
    c_ul_loc,
    c_ul_size,
    c_ul_range,
    c_ul_agent,
	c_ul_progress,
    c_ul_status,
#define UPLOADS_GUI_VISIBLE_COLUMNS ((guint) c_ul_status + 1)
#ifdef USE_GTK2
    c_ul_fg,
    c_ul_data,
#endif /* USE_GTK2 */

	c_ul_num
};

/**
 * Upload stats columns.
 */

enum c_us {
    c_us_filename,
    c_us_size,
    c_us_attempts,
    c_us_complete,
    c_us_norm,
	c_us_rtime,
	c_us_dtime,

#define UPLOAD_STATS_GUI_VISIBLE_COLUMNS ((guint) c_us_num)
	c_us_num
};

enum c_src {
	c_src_host,
	c_src_country,
	c_src_server,
	c_src_range,
	c_src_progress,
	c_src_status,

#define SOURCES_VISIBLE_COLUMNS ((guint) c_src_num)
	c_src_num
};

/**
 * Fileinfo table columns.
 */

enum c_fi {
	c_fi_filename,
	c_fi_size,
	c_fi_progress,
	c_fi_rx,
	c_fi_done,
	c_fi_uploaded,
	c_fi_sources,
	c_fi_created,
	c_fi_modified,
	c_fi_status,

#define FILEINFO_VISIBLE_COLUMNS ((guint) c_fi_num)
	c_fi_num
};

/**
 * Searches table columns.
 */

enum c_sr_columns {
    c_sr_filename,
	c_sr_ext,
    c_sr_charset,
    c_sr_size,
	c_sr_mime,
	c_sr_count,
    c_sr_loc,
    c_sr_vendor,
    c_sr_info,
    c_sr_route,
    c_sr_protocol,
    c_sr_hops,
    c_sr_ttl,
    c_sr_spam,
    c_sr_hostile,
    c_sr_owned,
    c_sr_sha1,
	c_sr_ctime,

#define SEARCH_RESULTS_VISIBLE_COLUMNS ((guint) c_sr_num)
	c_sr_num
};

/**
 * Gnet stats table columns.
 */

typedef enum {
    c_gs_type = 0,
    c_gs_received,
    c_gs_expired,
    c_gs_dropped,
    c_gs_queued,
    c_gs_relayed,
    c_gs_gen_queued,
    c_gs_generated,

	num_c_gs
} c_gs_t;

typedef enum {
    c_horizon_hops = 0,
    c_horizon_nodes,
    c_horizon_files,
    c_horizon_size,

    num_c_horizon
} c_horizon_t;

/**
 * Hostcache stats table columns.
 */
enum {
    c_hcs_name = 0,
    c_hcs_host_count,
    c_hcs_hits,
    c_hcs_misses
#define HCACHE_STATS_VISIBLE_COLUMNS ((guint) c_hcs_misses + 1)
};


/**
 * Searches overview table columns.
 */

enum {
    c_sl_name = 0,
    c_sl_hit,
    c_sl_new,
#define SEARCH_LIST_VISIBLE_COLUMNS ((guint) c_sl_new + 1)
#ifdef USE_GTK2
    c_sl_fg,
    c_sl_bg,
	c_sl_sch, /**< invisible, pointer to the search_t for this entry */
#endif
	c_sl_num
};

/**
 * Search stats table columns.
 */

enum {
    c_st_term = 0,
    c_st_period,
    c_st_total
};

#endif /* _gtk_columns_h_ */

/* vi: set ts=4 sw=4 cindent: */
