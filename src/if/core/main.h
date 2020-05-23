/*
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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

#ifndef _if_core_main_h_
#define _if_core_main_h_

#include "common.h"

#ifdef CORE_SOURCES

/**
 * Mode for gtk_gnutella_request_shutdown().
 */

enum shutdown_mode {
	GTKG_SHUTDOWN_NORMAL = 1,
	GTKG_SHUTDOWN_ASSERT,
	GTKG_SHUTDOWN_ERROR,
	GTKG_SHUTDOWN_MEMORY,
	GTKG_SHUTDOWN_SIGNAL
};

/**
 * Shutdown options.
 */

#define GTKG_SHUTDOWN_OFAST		(1U << 0) /**< BYE sent to supporting nodes */
#define GTKG_SHUTDOWN_ORESTART	(1U << 1) /**< Restart gtk-gnutella */
#define GTKG_SHUTDOWN_OCRASH	(1U << 2) /**< Crash restart */
#define GTKG_SHUTDOWN_OEXTEND	(1U << 3) /**< Extend session at next launch */

void gtk_gnutella_exit(int n);
void gtk_gnutella_request_shutdown(enum shutdown_mode mode, unsigned flags);
bool debugging(uint t);

char *main_command_line(void);
const char *gtk_version_string(void);

#endif /* CORE_SOURCES */
#endif /* _if_core_main_h_ */

/* vi: set ts=4 sw=4 cindent: */
