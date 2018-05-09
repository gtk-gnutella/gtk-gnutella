/*
 * sdbm - ndbm work-alike hashed database library
 *
 * Database temporary file tracking
 * author: Raphael Manfredi <Raphael_Manfredi@pobox.com>
 * status: public domain.
 *
 * @ingroup sdbm
 * @file
 * @author Raphael Manfredi
 * @date 2016
 */

#include "common.h"

#include "sdbm.h"
#include "tune.h"
#include "private.h"
#include "tmp.h"

#include "lib/compat_misc.h"
#include "lib/eslist.h"
#include "lib/fd.h"
#include "lib/file.h"
#include "lib/filelock.h"
#include "lib/halloc.h"
#include "lib/hstrfn.h"
#include "lib/misc.h"			/* For CONST_STRLEN() */
#include "lib/parse.h"
#include "lib/str.h"
#include "lib/tm.h"
#include "lib/walloc.h"

#include "lib/override.h"		/* Must be the last header included */

#define TMP_WAIT_MAX	5		/* # of seconds we accept to wait for lock */

#ifdef S_IROTH
#define TMP_FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)	/* 0644 */
#else
#define TMP_FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP)				/* 0640 */
#endif

enum tmp_action {
	TMP_ADD,
	TMP_REMOVE,
	TMP_CLEAN
};

typedef int (*tmp_action_t)(int *fdp, const char *ext, const DBM *db);

/**
 * Convert action into words.
 */
static const char *
tmp_action_to_string(const enum tmp_action action)
{
	switch (action) {
	case TMP_ADD:    return "add";
	case TMP_REMOVE: return "remove";
	case TMP_CLEAN:  return "clean";
	}

	g_assert_not_reached();
}

/**
 * Derive the filename to use for recording the temporary extensions.
 *
 * This is based on the .pag filename.  If that file bears the ".pag"
 * extension, it is simply replaced by a ".tmp".  Otherwise, we use the
 * .pag filename and append the ".tmp" suffix to it.
 *
 * @param db	the database
 *
 * @return a new string to be freed via hfree().
 */
static char *
tmp_filename(const DBM *db)
{
	str_t *s = str_new_from(db->pagname);
	size_t i;
	const char tmp[] = ".tmp";
	

	if (STR_HAS_SUFFIX(s, DBM_PAGFEXT, &i)) {
		str_replace(s, i, STR_CONST_LEN(DBM_PAGFEXT), tmp);
	} else {
		str_cat_len(s, tmp, CONST_STRLEN(tmp));
	}

	return str_s2c_null(&s);
}

/**
 * Unlink dead file if it exists.
 */
static void
tmp_unlink_file(const DBM *db, const char *file)
{
	if (file_exists(file) && -1 == unlink(file)) {
		s_warning("%s(): SDBM \"%s\": cannot unlink dead file %s: %m",
			G_STRFUNC, sdbm_name(db), file);
	}
}

/**
 * Remove all temporary files bearing the given extension.
 *
 * @param db	the database
 * @param ext	the trailing extension to look for
 */
static void
tmp_unlink_ext(const DBM *db, const char *ext)
{
	char *dirname, *pagname, *datname;

	dirname = h_strconcat(db->dirname, ext, NULL_PTR);
	pagname = h_strconcat(db->pagname, ext, NULL_PTR);
	datname =
		NULL == db->datname ? NULL : h_strconcat(db->datname, ext, NULL_PTR);

	tmp_unlink_file(db, dirname);
	tmp_unlink_file(db, pagname);
	if (datname != NULL)
		tmp_unlink_file(db, datname);

	HFREE_NULL(dirname);
	HFREE_NULL(pagname);
	HFREE_NULL(datname);
}

/**
 * Add "ext" at the end of the list in the file.
 *
 * @return 0 if OK, -1 on error.
 */
static int
tmp_run_add(int *fd, const char *ext, const DBM *db)
{
	str_t *s = str_new(32);
	int r;

	(void) db;

	str_printf(s, "%s %u\n", ext, getpid());
	r = write(*fd, str_2c(s), str_len(s));
	str_destroy_null(&s);

	return r;
}

/**
 * Parse line to extract extension string and pid.
 *
 * Upon success, "extension" is filled with the allocated extension string
 * and "pid" with the associated PID in the file.
 *
 * @return TRUE if successful, FALSE on error (and nothing allocated).
 */
static bool
tmp_parse_line(const char *line, char **extension, pid_t *pid)
{
	const char *s;
	char *ext;
	int error;

	/*
	 * Format of the line is: "string <space> PID".
	 */
	
	s = strchr(line, ' ');
	if (NULL == s)
		return FALSE;

	ext = h_strndup(line, ptr_diff(s, line));
	*pid = parse_uint32(s + 1, NULL, 10, &error);

	if (error) {
		HFREE_NULL(ext);
		return FALSE;
	}

	*extension = ext;
	return TRUE;
}

/**
 * Remove "ext" from the list in the .tmp file or all the dead files bearing
 * the extensions listed there when "ext" is NULL.
 *
 * @param fd		pointer to the fd opened on the .tmp file.
 * @param ext		the extension to remove (NULL means all "dead" files)
 * @param db		the database whose files we are cleaning up
 * @param caller	calling routine name, for logging
 *
 * @return 0 if OK, -1 on error.
 */
static int
tmp_clean_entries(int *fd, const char *ext, const DBM *db, const char *caller)
{
	FILE *f;
	char line[128];
	struct tmp_entry {
		char *extension;
		pid_t pid;
		slink_t next;
	} *e;
	eslist_t items;
	str_t *s;
	fileoffset_t pos;
	int ret = -1;
	size_t lineno = 0;

	f = fdopen(*fd, "r");
	if (NULL == f)
		return -1;

	eslist_init(&items, offsetof(struct tmp_entry, next));
	s = str_new(32);

	while (fgets(ARYLEN(line), f)) {
		char *extension;
		pid_t pid;
		struct tmp_entry *item;

		lineno++;

		if (!file_line_chomp_tail(ARYLEN(line), NULL)) {
			s_warning("%s(): SDBM \"%s\": line #%zu: too long a line \"%*s\","
				" attempting to resync",
				caller, sdbm_name(db), lineno,
				(int) clamp_strlen(ARYLEN(line)), line);
			continue;
		}

		if (!tmp_parse_line(line, &extension, &pid)) {
			/*
			 * Avoid warnings for empty lines.
			 */
			if (*line != '\0') {
				s_warning("%s(): SDBM \"%s\": line #%zu: skipping bad \"%s\"",
					caller, sdbm_name(db), lineno, line);
			}
			continue;
		}

		if (NULL == ext) {
			/* Cleaning up all "dead" entries */
			if (!compat_process_exists(pid)) {
				tmp_unlink_ext(db, extension);
				HFREE_NULL(extension);
				continue;
			}
		} else {
			/* Removing a specific extension from the .tmp file */
			if (0 == strcmp(extension, ext)) {
				/* That's the entry we wish to remove from the file */
				HFREE_NULL(extension);
				continue;
			}
		}

		/* These other entries will be re-written in the file */

		WALLOC0(item);
		item->extension = extension;
		item->pid = pid;

		eslist_append(&items, item);
	}

	/*
	 * Rewind the file, write all the items we need to keep and truncate
	 * the file at the end.
	 */

	if (0 != lseek(*fd, 0, SEEK_SET)) {
		errno = EIO;
		goto done;
	}

	ESLIST_FOREACH_DATA(&items, e) {
		int r;

		str_printf(s, "%s %u\n", e->extension, e->pid);
		r = write(*fd, str_2c(s), str_len(s));
		if (-1 == r)
			goto done;
	}

	pos = lseek(*fd, 0, SEEK_CUR);
	if (-1 == ftruncate(*fd, pos)) {
		s_warning("%s(): SDBM \"%s\": unable to truncate tmp file: %m",
			caller, sdbm_name(db));
		goto done;
	}

	ret = 0;		/* All OK */

	/* FALL THROUGH */

done:
	ESLIST_FOREACH_DATA(&items, e) {
		HFREE_NULL(e->extension);
	}
	eslist_wfree(&items, sizeof(struct tmp_entry));

	*fd = -1;	/* File descriptor belongs to the FILE object */
	fclose(f);
	str_destroy_null(&s);

	return ret;
}

/**
 * Cleanup the database, removing all files bearing the temporary extension
 * listed if they belong to a dead PID.
 *
 * @return 0 if OK, -1 on error.
 */
static int
tmp_run_clean(int *fd, const char *ext, const DBM *db)
{
	g_assert(NULL == ext);	/* Signals: "dead" entries cleanup */

	return tmp_clean_entries(fd, ext, db, G_STRFUNC);
}

/**
 * Remove "ext" from the list in the file.
 *
 * @return 0 if OK, -1 on error.
 */
static int
tmp_run_remove(int *fd, const char *ext, const DBM *db)
{
	g_assert(ext != NULL);	/* Signals: specific entry removal in .tmp */

	return tmp_clean_entries(fd, ext, db, G_STRFUNC);
}

/**
 * Process a temporary extension for the database.
 *
 * @param db		the database
 * @param ext		the temporary extension to process
 * @param action	action type, for logging
 * @param cb		the callback to invoke for processing
 */
static void
tmp_process(
	const DBM *db, const char *ext,
	enum tmp_action action, tmp_action_t cb)
{
	char *tmpfile = tmp_filename(db), *lockfile;
	tm_t tmout;
	filelock_t *fl;
	int fd = -1, flags = 0;
	bool error = FALSE;
	static const char lck[] = ".lck";

	sdbm_check(db);
	g_assert(cb != NULL);

	/*
	 * If we are not adding a new entry, check whether the .tmp file exists.
	 * before attempting to lock it.
	 */

	if (TMP_ADD != action && !file_exists(tmpfile))
		goto nothing;

	/*
	 * Lock .tmp file, waiting at most TMP_WAIT_MAX seconds for the lock.
	 *
	 * Normally contention on that file will be extremely rare, so there is
	 * no need to wait for a long time before bailing out.
	 *
	 * Note that we may not have a lock on the DB, and the .tmp file can
	 * be re-written, which is why we need this external lock to be taken
	 * to prevent any race.
	 */

	tmout.tv_sec  = TMP_WAIT_MAX;
	tmout.tv_usec = 0;

	lockfile = h_strconcat(tmpfile, lck, NULL_PTR);
	fl = filelock_timed_create(lockfile, NULL, &tmout);
	HFREE_NULL(lockfile);

	if (NULL == fl) {
		s_carp("%s(): SDBM \"%s\": "
			"cannot %s extension \"%s\" in %s: cannot lock: %m",
			G_STRFUNC, sdbm_name(db),
			tmp_action_to_string(action), ext, tmpfile);
		goto done;
	}

	switch (action) {
	case TMP_ADD:
		flags = O_CREAT | O_WRONLY | O_APPEND;
		break;
	case TMP_CLEAN:
	case TMP_REMOVE:
		/* Recheck presence now that we have the file lock */
		if (!file_exists(tmpfile))
			goto done;
		flags = O_RDWR;
		break;
	}

	fd = file_open(tmpfile, flags, TMP_FILE_MODE);
	if (-1 == fd)
		goto done;

	if (-1 == (*cb)(&fd, ext, db)) {
		error = TRUE;
		s_carp("%s(): SDBM \"%s\": "
			"cannot %s extension \"%s\" in %s: %m",
			G_STRFUNC, sdbm_name(db),
			tmp_action_to_string(action), ext, tmpfile);

		/* FALL THROUGH */
	}

	/* FALL THROUGH */

done:
	if (-1 == fd_close(&fd) && !error) {
		s_carp("%s(): SDBM \"%s\": close() %s to %s extension \"%s\": %m",
			G_STRFUNC, sdbm_name(db),
			tmpfile, tmp_action_to_string(action), ext);
	}

	if (file_is_empty(tmpfile)) {
		if (-1 == unlink(tmpfile))
			s_warning("%s(): cannot unlink empty %s: %m", G_STRFUNC, tmpfile);
	}

	filelock_free_null(&fl);

	/* FALL THROUGH */

nothing:
	HFREE_NULL(tmpfile);
}

/**
 * Record a new temporary extension for the database.
 *
 * This is typically used when an asynchronous rebuild is attempted on
 * the base.  In case the process is interrupted before we can cleanup,
 * a call to sdbm_cleanup() will remove all the old temporary files that
 * are no longer used.
 *
 * @param db	the database
 * @param ext	the temporary extension appeded to .dir, .pag and .dat files
 */
void
tmp_add(const DBM *db, const char *ext)
{
	tmp_process(db, ext, TMP_ADD, tmp_run_add);
}

/**
 * Remove a temporary extension for the database.
 *
 * This is called when the process is done with the temporary file.
 *
 * @param db	the database
 * @param ext	the temporary extension appeded to .dir, .pag and .dat files
 */
void
tmp_remove(const DBM *db, const char *ext)
{
	tmp_process(db, ext, TMP_REMOVE, tmp_run_remove);
}

/**
 * Remove all dead files bearing temporary extensions associated with database.
 *
 * A dead entry is one bearing an extension listed in the temporary file which
 * is further associated with a dead PID.
 *
 * @param db	the database
 */
void
tmp_clean(const DBM *db)
{
	tmp_process(db, NULL, TMP_CLEAN, tmp_run_clean);
}

/* vi: set ts=4 sw=4 cindent: */
