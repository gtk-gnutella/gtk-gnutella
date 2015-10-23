/*
 * Copyright (c) 2015 Raphael Manfredi
 *
 * The fcntl() logic implemented here for locking is:
 * Copyright (c) 2005 Christian Biere
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
 * Locks taken via filelock_create() are auto-cleaned by default when the
 * process exits, but not when a fork()ed child exits.
 *
 * To release a lock explicitly, use filelock_free_null().
 *
 * Note that these locks are advisory locks only and require that all the
 * contendents be requesting permission via filelock_create() on the same path.
 *
 * Although filelock_create() takes paramters, applications establishing a
 * locking protocol on a given file must consistently use the same parameters
 * to grab the lock.  Key parameters are "pid_only" and "fd_unlock".
 *
 * Implementation notes:
 *
 * If the kernel and the targeted filesystem support fcntl() locking, then
 * fcntl() is the preferred way of obtaining the lock.  Users can request that
 * locking be done via a PID file only, but this is not recommended as this
 * is full of race conditions that we attempt to fight as best as we can, but
 * we can only reduce the opportunities for misbehaviour, not close all the
 * loopholes.
 *
 * On Windows systems, fcntl() locks are mandatory locks, not advisory ones.
 * As such, the file is only locked during the critical section where we read
 * the existing PID and write our PID.  This is different (and stronger) than
 * just requesting a "pid_only" locking mode.  So "fd_unlock" is implied and
 * cannot be turned off.
 *
 * @author Raphael Manfredi
 * @date 2015
 */

#include "common.h"

#include "filelock.h"

#include "compat_misc.h"
#include "compat_usleep.h"
#include "elist.h"
#include "fd.h"
#include "file.h"
#include "log.h"
#include "misc.h"		/* For is_temporary_error() */
#include "once.h"
#include "parse.h"
#include "random.h"
#include "spinlock.h"
#include "str.h"
#include "stringify.h"
#include "timestamp.h"
#include "tm.h"
#include "xmalloc.h"

#include "override.h"		/* Must be the last header included */

static const mode_t FILELOCK_MODE = S_IRUSR | S_IWUSR; 	/* 0600 */

enum filelock_magic { FILELOCK_MAGIC = 0x1e773759 };

/**
 * A file lock.
 */
struct filelock {
	enum filelock_magic magic;		/**< Magic number */
	uint noclean:1;					/**< If set, lock will not auto-clean */
	int fd;							/**< fcntl() lock file */
	pid_t pid;						/**< Process that created the lock */
	char *path;						/**< Lock file path */
	link_t fl_link;					/**< Links all file locks together */
};

static inline void
filelock_check(const struct filelock * const fl)
{
	g_assert(fl != NULL);
	g_assert(FILELOCK_MAGIC == fl->magic);
}

/**
 * All the auto-cleaned locks are linked together.
 */
static elist_t filelock_vars = ELIST_INIT(offsetof(filelock_t, fl_link));
static spinlock_t filelock_vars_slk = SPINLOCK_INIT;

#define FILELOCK_VARS_LOCK		spinlock(&filelock_vars_slk)
#define FILELOCK_VARS_UNLOCK	spinunlock(&filelock_vars_slk)

static once_flag_t filelock_inited;

/**
 * Add new lock to the global lock list.
 */
static void
filelock_vars_add(filelock_t *fl)
{
	filelock_check(fl);

	FILELOCK_VARS_LOCK;
	elist_append(&filelock_vars, fl);
	FILELOCK_VARS_UNLOCK;
}

/**
 * Remove lock from the global lock list.
 */
static void
filelock_vars_remove(filelock_t *fl)
{
	filelock_check(fl);

	FILELOCK_VARS_LOCK;
	elist_remove(&filelock_vars, fl);
	FILELOCK_VARS_UNLOCK;
}

/**
 * Unlock filelock.
 */
static void
filelock_unlock(filelock_t *fl)
{
	filelock_check(fl);

	/*
	 * There is a small race condition here because we close the fcntl()
	 * file descriptor before unlinking the file.  Another process could
	 * come-in and attenpt to create the file, lock it and then we would
	 * remove it underneath.
	 *
	 * Doing things the other way round would create problems on Windows,
	 * so we have to cope with that race condition at lock creation time,
	 * which accounts for much of the complexity of filelock_create().
	 *		--RAM, 2015-10-20
	 */

	fd_forget_and_close(&fl->fd);
	if (-1 == unlink(fl->path))
		s_miniwarn("%s(): cannot remove \"%s\": %m", G_STRFUNC, fl->path);
}

/**
 * Free lock, unlinking the file and destroying the object.
 *
 * @param fl			the filelock to destroy
 * @param autoclean		if TRUE, autocleaning is in progress
 */
static void
filelock_free(filelock_t *fl, bool autoclean)
{
	filelock_check(fl);

	/*
	 * Because this routine can be called at exit time, very late, we make
	 * sure all memory allocation is done via xmalloc() and the cleanup
	 * handler makes sure memory freeing is disabled to avoid problems.
	 */

	filelock_unlock(fl);
	xfree(fl->path);

	if (!autoclean && !fl->noclean)
		filelock_vars_remove(fl);

	fl->magic = 0;
	xfree(fl);
}

/**
 * Free lock, unlinking the file and nullifying the lock pointer.
 *
 * This effectively releases the lock we had taken.
 */
void
filelock_free_null(filelock_t **fl_ptr)
{
	filelock_t *fl = *fl_ptr;

	if (fl != NULL) {
		filelock_free(fl, FALSE);
		*fl_ptr = NULL;
	}
}

/**
 * Embedded list iterator callback to clean the lock.
 */
static bool
filelock_clean(void *data, void *udata)
{
	filelock_t *fl = data;
	pid_t pid = pointer_to_ulong(udata);

	filelock_check(fl);

	/*
	 * Because an atexit() cleanup is inherited by children, we need to make
	 * sure we're only cleaning locks taken by this process!
	 */

	if (fl->pid != pid)
		return FALSE;		/* Keep it in list */

	/*
	 * Avoid any memory allocation so late in the process, so use a logging
	 * routine that is guaranteed to never allocate memory and which
	 * will by-pass stdio as well.
	 */

	s_miniwarn("%s(): unlocking %s", G_STRFUNC, fl->path);

	filelock_free(fl, TRUE);
	return TRUE;			/* Remove from list */
}

/**
 * Auto-cleaning routine invoked at exit() time.
 */
static void
filelock_autoclean(void)
{
	pid_t pid = getpid();

	xmalloc_stop_freeing();		/* Avoid freeing the locks physically */

	FILELOCK_VARS_LOCK;
	elist_foreach_remove(&filelock_vars, filelock_clean, ulong_to_pointer(pid));
	FILELOCK_VARS_UNLOCK;
}

/**
 * Once routine initializing the auto-cleaning of file locks.
 */
static void
filelock_init_once(void)
{
	atexit(filelock_autoclean);
}

/**
 * Read PID from specified file.
 *
 * @param fd	opened file from which we want to read a PID
 *
 * @return the read PID, 0 if we cannot parse it with errno set.
 */
static pid_t
filelock_read_pid(int fd)
{
	ssize_t r;
	char buf[UINT64_DEC_BUFLEN];
	uint64 u;
	int error;

	/*
	 * Since we don't expect any errors from the system calls, we trace
	 * them loudly, showing the calling stack to give context given we
	 * only have the file descriptor down here...
	 */

	if (0 != lseek(fd, 0, SEEK_SET)) {
		s_carp("%s(): cannot seek to start of fd #%d: %m", G_STRFUNC, fd);
		return 0;
	}

	r = read(fd, buf, sizeof buf - 1);

	if ((ssize_t) -1 == r) {
		s_carp("%s(): cannot read from fd #%d: %m", G_STRFUNC, fd);
		return 0;
	}

	/* Check the PID in the file */

	g_assert(r >= 0 && (size_t) r < sizeof buf);
	buf[r] = '\0';

	u = parse_uint64(buf, NULL, 10, &error);
	if (error) {
		errno = error;
		return 0;			/* Could not parse PID */
	}

	if (u <= 1) {
		errno = EDOM;		/* Out of exepected domain! */
		return 0;
	}

	return (pid_t) u;
}

/**
 * Write our PID into specified file descriptor.
 *
 * @return 0 if OK, -1 on error with errno set.
 */
static int
filelock_write_pid(int fd, pid_t ourpid)
{
	size_t w;
	ssize_t r;
	char buf[ULONG_DEC_BUFLEN + 1];		/* +1 for "\n", since NUL is included */

	w = str_bprintf(buf, sizeof buf, "%ld\n", (ulong) ourpid);

	/*
	 * Since we don't expect any errors from the system calls, we trace
	 * them loudly, showing the calling stack to give context given we
	 * only have the file descriptor down here...
	 */

	if (0 != lseek(fd, 0, SEEK_SET)) {
		s_carp("%s(): cannot seek to start fd #%d: %m", G_STRFUNC, fd);
		return -1;
	}

	if (-1 == ftruncate(fd, 0))	{
		s_carp("%s(): cannot truncate fd #%d: %m", G_STRFUNC, fd);
		return -1;
	}

	r = write(fd, buf, w);

	if ((ssize_t) -1 == r) {
		s_carp("%s(): cannot write %zu byte%s to fd #%d: %m",
			G_STRFUNC, w, plural(w), fd);
		return -1;
	}

	if (UNSIGNED(r) != w) {
		s_carp("%s(): could only write %zd byte%s out of %zu to fd #%d",
			G_STRFUNC, r, plural(r), w, fd);
		errno = ENOSPC;		/* Assume it's a filesystem space problem */
		return -1;
	}

	return 0;
}

/**
 * Do they want to close the fd of the lock file after writing a PID into it,
 * in effect unlocking the lock file?
 */
static inline bool
filelock_is_fd_unlock(const filelock_params_t *p)
{
	/*
	 * On Windows, since our fcntl(F_WRLCK) implementation relies on native
	 * locks which are mandatory, we do not want to keep the lock file
	 * locked because that prevents other processes from reading it and
	 * seeing which PID locked the file -- there is no fcntl(F_GETLK) possible.
	 *		--RAM, 2015-10-23
	 */

	if (is_running_on_mingw()) {
		return TRUE;		/* Always TRUE */
	} else {
		return p != NULL && p->fd_unlock;
	}
}

/**
 * Do they want to avoid auto-cleaning for the taken lock?
 */
static inline bool
filelock_is_noclean(const filelock_params_t *p)
{
	return p != NULL && p->noclean;
}

/**
 * Do they want "PID-only" locking?
 */
static inline bool
filelock_is_pid_only(const filelock_params_t *p)
{
	return p != NULL && p->pid_only;
}

/**
 * Are we in "check-only" mode?
 */
static inline bool
filelock_is_check_only(const filelock_params_t *p)
{
	return p != NULL && p->check_only;
}

/**
 * Are we in "debug" mode?
 */
static inline bool
filelock_is_debug(const filelock_params_t *p)
{
	return p != NULL && p->debug;
}

#define FILELOCK_MAX_RESTARTS	5			/* How many times can we restart */
#define FILELOCK_MAX_OPENS		100			/* How many open() can we do? */
#define FILELOCK_MAX_AGE		2			/* (s) File is stale if older */

/**
 * Sleep randomly between 100 and 5000 usecs.
 */
static void
filelock_usleep(const filelock_params_t *p, const char *caller)
{
	uint us = 100 + random_value(4900);

	if (filelock_is_debug(p)) {
		s_debug("%s(): sleeping for %u usec%s", caller, us, plural(us));
	}

	compat_usleep(us);
}

/**
 * Create a lockfile.
 *
 * The optional ``p'' argument (can be NULL) is used to customize the logic:
 *
 *   p->debug       decisions taken by the locking algorithm are traced.
 *   p->noclean     lock will not be auto-cleaned at process exit time
 *   p->pid_only    request that we only use weaker PID-file locking logic
 *   p->check_only  check whether we could take the lock, errno=ESTALE if OK
 *   p->fd_unlock   unlock lockfile after writing PID, by closing it
 *
 * @param path	the path to the lockfile (copied)
 * @param p		(optional) custom locking parameters
 *
 * @return a lockfile object on success, NULL on error with errno set:
 *
 * ESTALE if we could have got the lock, had we not been in check-only mode
 * EEXIST if the lock could not be taken
 * Other codes probably mean an error during file operations.
 */
filelock_t *
filelock_create(const char *path, const filelock_params_t *p)
{
	bool locked, existed;
	int fd = -1;
	int attempts = 0, restarts = 0;
	filelock_t *f;
	pid_t ourpid = getpid();

	g_assert(path != NULL);

restart:
	locked = FALSE;
	existed = FALSE;

	if (restarts++) {
		fd_forget_and_close(&fd);
		if (restarts >= FILELOCK_MAX_RESTARTS) {
			if (filelock_is_debug(p)) {
				s_debug("%s(): too many restarts for \"%s\"", G_STRFUNC, path);
			}
			goto failed;
		}
		filelock_usleep(p, G_STRFUNC);
	}

	g_assert_log(-1 == fd,
		"%s(): fd=%d, restarts=%d", G_STRFUNC, fd, restarts);

reopen:
	fd = open(path, O_RDWR | O_CREAT | O_EXCL, FILELOCK_MODE);
	if (fd < 0) {
		if (EEXIST == errno) {
			fd = open(path, O_RDWR);
			if (fd < 0) {
				/* Hit a race condition, retry */
				if (ENOENT == errno && attempts++ < FILELOCK_MAX_OPENS) {
					filelock_usleep(p, G_STRFUNC);
					goto reopen;
				}
				/* FALL THROUGH -- unexpected error */
			} else {
				existed = TRUE;
				goto opened;
			}
		}
		s_warning("%s(): can't open nor create \"%s\": %m", G_STRFUNC, path);
		return NULL;
	}

opened:
	if (filelock_is_debug(p)) {
		s_debug("%s(): %s \"%s\"",
			G_STRFUNC, existed ? "opened" : "created", path);
	}

/* FIXME: These might be enums, a compile-time check would be better */
#if defined(F_SETLK) && defined(F_WRLCK)
	if (!filelock_is_pid_only(p)) {
		struct flock fl;
		bool locking_failed;

		ZERO(&fl);
		fl.l_type = F_WRLCK;
		fl.l_whence = SEEK_SET;
		/* l_start and l_len are zero, which means the whole file is locked */

		locking_failed = -1 == fcntl(fd, F_SETLK, &fl);

		if (filelock_is_debug(p)) {
			s_debug("%s(): fcntl-locking \"%s\" %s",
				G_STRFUNC, path, locking_failed ? "failed" : "succeeded");
		}

		if (locking_failed) {
			int saved_errno = errno;

			if (!filelock_is_check_only(p) || filelock_is_debug(p)) {
				/*
				 * Use F_GETLK to determine the PID of the process, the
				 * reinitialization of "fl" might be unnecessary but who
				 * knows.
				 */

				ZERO(&fl);
				fl.l_type = F_WRLCK;
				fl.l_whence = SEEK_SET;

				if (filelock_is_debug(p)) {
					s_warning("%s(): fcntl(%d, F_SETLK, ...) failed "
						"for \"%s\": %m",
						G_STRFUNC, fd, path);
				}

				/*
				 * If we're crashing and restarting automatically, we'll have
				 * the same PID as the lock and that is OK.
				 */

				if (-1 != fcntl(fd, F_GETLK, &fl)) {
					if (ourpid == fl.l_pid) {
						if (filelock_is_debug(p)) {
							s_debug("%s(): lock already owned (PID=%lu)",
								G_STRFUNC, (ulong) fl.l_pid);
						}
						locked = TRUE;
					} else {
						if (filelock_is_debug(p)) {
							s_debug("%s(): file \"%s\" is locked by PID=%lu",
								G_STRFUNC, path, (ulong) fl.l_pid);
						}
					}
				} else {
					s_warning("%s(): fcntl(%d, F_GETLK, ...) failed "
						"for \"%s\": %m",
						G_STRFUNC, fd, path);
				}
			}

			if (is_temporary_error(saved_errno) || EACCES == saved_errno) {
				goto failed;	/* The file seems to be locked */
			}
		} else {
			locked = TRUE;
		}
	}
#else	/* !F_SETLK || !F_WRLCK */
	if (!filelock_is_pid_only(p)) {
		s_carp_once("%s(): no fcntl() locking available, using PID-file only",
			G_STRFUNC);
	}
#endif	/* F_SETLK && F_WRLCK */

	/*
	 * Maybe F_SETLK is not supported by the OS or filesystem?
	 * Fall back to weaker PID locking
	 *
	 * When we release the lock after writing the PID, we cannot assume
	 * we got the lock -- we just got exclusive access to the file to
	 * be able to write our PID without races!
	 */

	if (!locked || filelock_is_fd_unlock(p)) {
		pid_t pid;
		filestat_t buf_fd, buf_path;

		/*
		 * If the lockfile did not exist, we have it because we managed to
		 * create the file atomically (O_CREAT | O_EXCL).
		 */

		if (!existed) {
			if (filelock_is_debug(p)) {
				s_debug("%s(): created \"%s\" atomically, taking lock!",
					G_STRFUNC, path);
			}
			goto locked;
		}

		/* Check the PID in the file */

		if (filelock_is_debug(p)) {
			s_debug("%s(): reading \"%s\" for PID", G_STRFUNC, path);
		}

		pid = filelock_read_pid(fd);

		/* If the pidfile seems to be corrupted, ignore it */

		if (pid != 0) {
			if (filelock_is_debug(p)) {
				s_debug("%s(): checking whether PID %lu is alive",
					G_STRFUNC, (ulong) pid);
			}
			if (compat_process_is_alive(pid)) {
				if (ourpid == pid) {
					if (filelock_is_debug(p)) {
						s_debug("%s(): it is our PID!", G_STRFUNC);
					}
					goto locked;	/* It's our PID, we have the lock */
				}
				if (!filelock_is_check_only(p)) {
					s_warning("%s(): file \"%s\" already used by PID=%lu",
						G_STRFUNC, path, (ulong) pid);
				}
				goto failed;
			} else if (filelock_is_debug(p)) {
				s_debug("%s(): PID %lu is dead", G_STRFUNC, (ulong) pid);
			}
		}

		/* If the pidfile is locked, we got our lock anyway */

		if (locked) {
			if (filelock_is_debug(p)) {
				s_debug("%s(): got right to lock since we fcntl()-locked file",
					G_STRFUNC);
			}
			goto locked;			/* We'll write our PID in the lockfile */
		}

		/*
		 * File did exist, with no valid / alive PID found.
		 *
		 * We're going to check that the file we have opened still exists
		 * on the disk, and that it is identical.  If not, then we are in
		 * the middle of a race condition and it's best to bail out.
		 */

		if (!file_exists(path)) {
			if (filelock_is_debug(p)) {
				s_debug("%s(): file \"%s\" now gone, found race condition #1",
					G_STRFUNC, path);
			}
			goto failed;
		}

		if (-1 == fstat(fd, &buf_fd)) {
			s_warning("%s(): fstat(%d) failed for \"%s\": %m",
				G_STRFUNC, fd, path);
			goto failed;
		}

		/*
		 * If there was no PID in the file and it is "recent", we may be
		 * facing a race condition whereby another process created the file
		 * but did not have time yet to write its PID.  Restart from the
		 * beginning!
		 */

		if (delta_time(tm_time_exact(), buf_fd.st_mtime) < FILELOCK_MAX_AGE) {
			if (filelock_is_debug(p)) {
				time_delta_t age = delta_time(tm_time(), buf_fd.st_mtime);
				s_debug("%s(): file \"%s\" recent: %d sec%s old, retrying...",
					G_STRFUNC, path, (int) age, plural(age));
			}
			goto restart;
		}

		filelock_usleep(p, G_STRFUNC);		/* Let the race begin */

		if (-1 == stat(path, &buf_path)) {
			if (filelock_is_debug(p)) {
				s_debug("%s(): file \"%s\" now gone, found race condition #2",
					G_STRFUNC, path);
			}
			goto failed;
		}

		if (
			buf_path.st_dev != buf_fd.st_dev ||
			buf_path.st_ino != buf_fd.st_ino ||
			buf_path.st_mtime != buf_fd.st_mtime
		) {
			if (filelock_is_debug(p)) {
				s_debug("%s(): file \"%s\" changed, found race condition #3",
					G_STRFUNC, path);
			}
			goto failed;
		}

		/*
		 * When was the file last changed?  If it's "old enough", more than a
		 * few seconds, then it's probably stale: close it, unlink it and
		 * restart from the beginning after waiting for some random time.
		 */

		if (delta_time(tm_time_exact(), buf_fd.st_mtime) > FILELOCK_MAX_AGE) {
			if (filelock_is_debug(p)) {
				time_delta_t age = delta_time(tm_time(), buf_fd.st_mtime);
				s_debug("%s(): file \"%s\" is %d sec%s old, retrying...",
					G_STRFUNC, path, (int) age, plural(age));
			}
			if (-1 == unlink(path)) {
				if (ENOENT == errno) {
					if (filelock_is_debug(p)) {
						s_debug("%s(): file \"%s\" gone, in race condition #4",
							G_STRFUNC, path);
					}
					goto failed;
				}
				s_warning("%s(): cannot unlink \"%s\": %m", G_STRFUNC, path);
				goto failed;
			}

			goto restart;
		}

		/* FALL THROUGH -- assume file was locked */
	}

locked:

	if (filelock_is_debug(p)) {
		s_debug("%s(): file \"%s\" LOCKED (%s mode)",
			G_STRFUNC, path, filelock_is_check_only(p) ? "check" :
			(locked || !existed) ? "permanent" : "hopeful");
	}

	if (filelock_is_check_only(p)) {
		fd_forget_and_close(&fd);
		if (-1 == unlink(path)) {
			s_warning("%s(): cannot unlink \"%s\": %m", G_STRFUNC, path);
		}
		errno = ESTALE;			/* Lock could be taken */
		return NULL;
	}

	/*
	 * Take ownership of the file by writing our PID
	 */

	if (-1 == filelock_write_pid(fd, ourpid)) {
		s_warning("%s(): cannot write our PID %lu into \"%s\": %m",
			G_STRFUNC, (ulong) ourpid, path);
		goto failed;
	}

	/*
	 * If we do not have a kernel lock on the file, be extra safe if we were
	 * not able to atomically create the file: wait a little bit and re-check
	 * that the file is still there and contains our PID.
	 */

	if (!locked && existed) {
		int lfd;
		pid_t pid;

		filelock_usleep(p, G_STRFUNC);		/* Let the race continue */
		lfd = open(path, O_RDONLY);

		if (-1 == lfd) {
			if (filelock_is_debug(p)) {
				s_debug("%s(): cannot reopen \"%s\", in race condition #5: %m",
					G_STRFUNC, path);
			}
			goto failed;
		}

		pid = filelock_read_pid(lfd);
		fd_close(&lfd);

		if (ourpid != pid) {
			if (filelock_is_debug(p)) {
				s_debug("%s(): foreign PID %ld in \"%s\", in race condition #6",
					G_STRFUNC, (ulong) pid, path);
			}
			goto failed;
		}
	}

	/*
	 * We obtained the lock.
	 *
	 * We use our malloc() layer here on purpose, because the locks can be
	 * disposed of very late when auto-cleaning triggers.
	 */

	once_flag_run(&filelock_inited, filelock_init_once);

	if (filelock_is_pid_only(p) || filelock_is_fd_unlock(p))
		fd_forget_and_close(&fd);

	XMALLOC0(f);
	f->magic = FILELOCK_MAGIC;
	f->noclean = booleanize(filelock_is_noclean(p));
	f->fd = fd;
	f->pid = ourpid;
	f->path = xstrdup(path);

	if (!f->noclean)
		filelock_vars_add(f);

	return f;

failed:

	if (filelock_is_debug(p)) {
		s_debug("%s(): file \"%s\" NOT LOCKED", G_STRFUNC, path);
	}
	fd_forget_and_close(&fd);
	errno = EEXIST;
	return NULL;
}

/**
 * Convenience routine to extract the PID written in a lock file.
 *
 * @param path		the lock file to check
 *
 * @return the PID contained in the file, 0 if we could not read it.
 */
pid_t
filelock_pid(const char *path)
{
	int fd;
	pid_t pid;

	if (-1 == (fd = open(path, O_RDONLY)))
		return 0;

	pid = filelock_read_pid(fd);
	fd_close(&fd);

	return pid;
}

/* vi: set ts=4 sw=4 cindent: */
