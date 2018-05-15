/*
 * Copyright (c) 2015 Raphael Manfredi
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
 * Win32 dynamic library patcher.
 *
 * @author Raphael Manfredi
 * @date 2015
 */

#ifndef _win32dlp_h_
#define _win32dlp_h_

/*
 * Public interface.
 */

void win32dlp_init(void *reserved, size_t size);
void win32dlp_exiting(void);

uint64 win32dlp_loaded_library_count(void);

struct logagent;

void win32dlp_show_settings_log(struct logagent *la);
void win32dlp_dump_stats_log(struct logagent *la, unsigned options);

#endif	/* _win32dlp_h_ */

/* vi: set ts=4 sw=4 cindent: */
