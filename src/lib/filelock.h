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
 * File locks.
 *
 * @author Raphael Manfredi
 * @date 2015
 */

#ifndef _filelock_h_
#define _filelock_h_

typedef struct filelock filelock_t;

/**
 * Filelock parameters (options).
 */
typedef struct filelock_params {
	bool debug;			/**< Whether to trace decisions, for debugging */
	bool noclean;		/**< Do not register lock for autoclean at exit() */
	bool pid_only;		/**< Don't attempt fcntl() locking, use a PID file */
	bool check_only;	/**< Check whether lock is taken (EEXIST / ESTALE) */
} filelock_params_t;

/*
 * Interface routines.
 */

filelock_t *filelock_create(const char *path, const filelock_params_t *p);
void filelock_free_null(filelock_t **fl_ptr);
pid_t filelock_pid(const char *path);

#endif	/* _filelock_h_ */

/* vi: set ts=4: */
