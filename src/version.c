/*
 * $Id$
 *
 * Copyright (c) 2002, Raphael Manfredi
 *
 * Version management.
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

#include "gnutella.h"

#include <ctype.h>				/* For isalpha() */
#include <sys/utsname.h>		/* For uname() */

#include "version.h"
#include "token.h"

RCSID("$Id$");

gchar *version_number = NULL;
gchar *version_string = NULL;

static version_t our_version;
static version_t last_rel_version;
static version_t last_dev_version;

/*
 * version_dump
 *
 * Dump original version string and decompiled form to stdout.
 */
static void version_dump(
	const guchar *str, const version_t *ver, const gchar *cmptag)
{
	printf("VERSION%s \"%s\":\n"
		"\tmajor=%u minor=%u patch=%u tag=%c taglevel=%u\n",
		cmptag, str, ver->major, ver->minor, ver->patchlevel,
		ver->tag ? ver->tag : ' ', ver->taglevel);
}

/*
 * version_str
 *
 * Return a user-friendly description of the version.
 * NB: returns pointer to static data.
 */
const gchar *version_str(const version_t *ver)
{
	static gchar str[80];
	gint rw;

	rw = gm_snprintf(str, sizeof(str), "%u.%u", ver->major, ver->minor);

	if (ver->patchlevel)
		rw += gm_snprintf(&str[rw], sizeof(str)-rw, ".%u", ver->patchlevel);

	if (ver->tag) {
		rw += gm_snprintf(&str[rw], sizeof(str)-rw, "%c", ver->tag);
		if (ver->taglevel)
			rw += gm_snprintf(&str[rw], sizeof(str)-rw, "%u", ver->taglevel);
	}

	if (ver->timestamp) {
		struct tm *tmp = localtime(&ver->timestamp);
		rw += gm_snprintf(&str[rw], sizeof(str)-rw, " (%02d/%02d/%d)",
			tmp->tm_mday, tmp->tm_mon + 1, tmp->tm_year + 1900);
	}

	return str;
}

/*
 * version_stamp
 *
 * Parse gtk-gnutella's version number in User-Agent/Server string `str'
 * and extract timestamp into `ver'.
 */
static void version_stamp(const guchar *str, version_t *ver)
{
	static gchar stamp[256];
	const guchar *p;

	ver->timestamp = 0;

	/*
	 * A typical vendor string with a timestamp would look like:
	 *
	 *    gtk-gnutella/0.85 (04/04/2002; X11; FreeBSD 4.6-STABLE i386)
	 *
	 * The date stamp is formattted as DD/MM/YYYY.
	 */

	p = strchr(str, '(');
	if (p) {
		const guchar *end;

		p++;
		end = strchr(p, ';');
		if (end) {
			time_t now = time(NULL);

			/*
			 * Using date2time() will allow us to possibly change the date
			 * format in the future, without impacting the ability of older
			 * servents to parse it.
			 */

			gm_snprintf(stamp, MIN(end - p + 1, sizeof(stamp)), "%s", p);
			ver->timestamp = date2time(stamp, &now);

			if (ver->timestamp == -1) {
				ver->timestamp = 0;
				g_warning("could not parse timestamp \"%s\" in \"%s\"", p, str);
			}
		} else
			g_warning("no timestamp in \"%s\"", str);
	}
}


/*
 * version_parse
 *
 * Parse gtk-gnutella's version number in User-Agent/Server string `str'
 * and extract relevant information into `ver'.
 *
 * Returns TRUE if we parsed a gtk-gnutella version correctly, FALSE if we
 * were not facing a gtk-gnutella version, or if we did not recognize it.
 */
static gboolean version_parse(const guchar *str, version_t *ver)
{
	const guchar *v;

	/*
	 * Modern version numbers are formatted like this:
	 *
	 *    gtk-gnutella/0.85 (04/04/2002; X11; FreeBSD 4.6-STABLE i386)
	 *    gtk-gnutella/0.90u (24/06/2002; X11; Linux 2.4.18-pre7 i686)
	 *    gtk-gnutella/0.90b (24/06/2002; X11; Linux 2.4.18-2emi i686)
	 *    gtk-gnutella/0.90b2 (24/06/2002; X11; Linux 2.4.18-2emi i686)
	 *
	 * The letter after the version number is either 'u' for unstable, 'a'
	 * for alpha, 'b' for beta, or nothing for a stable release.  It can be
	 * followed by digits when present.
	 *
	 * In prevision for future possible extensions, we also parse
	 *
	 *    gtk-gnutella/0.90.1b2 (24/06/2002; X11; Linux 2.4.18-2emi i686)
	 *
	 * where the third number is the "patchlevel".
	 */

	if (0 != strncmp(str, "gtk-gnutella/", 13))
		return FALSE;

	v = str + 13;

	if (
		5 == sscanf(v, "%u.%u.%u%c%u",
			&ver->major, &ver->minor, &ver->patchlevel,
			&ver->tag, &ver->taglevel)
	)
		goto ok;

	ver->taglevel = 0;

	if (
		4 == sscanf(v, "%u.%u.%u%c",
			&ver->major, &ver->minor, &ver->patchlevel, &ver->tag)
	) {
		if (!isalpha(ver->tag))		/* Not a letter */
			ver->tag = '\0';
		goto ok;
	}

	ver->tag = '\0';

	if (
		3 == sscanf(v, "%u.%u.%u",
			&ver->major, &ver->minor, &ver->patchlevel)
	)
		goto ok;

	ver->patchlevel = 0;

	if (
		4 == sscanf(v, "%u.%u%c%u",
			&ver->major, &ver->minor, &ver->tag, &ver->taglevel)
	)
		goto ok;

	ver->taglevel = 0;

	if (3 == sscanf(v, "%u.%u%c", &ver->major, &ver->minor, &ver->tag)) {
		if (!isalpha(ver->tag))		/* Not a letter */
			ver->tag = '\0';
		goto ok;
	}

	ver->tag = '\0';

	if (2 == sscanf(v, "%u.%u", &ver->major, &ver->minor))
		goto ok;

	return FALSE;

ok:
	if (dbg > 6)
		version_dump(str, ver, "#");

	return TRUE;
}

/*
 * version_tagcmp
 *
 * Compare two tag chars, assuming version numbers are equal.
 * Returns -1, 0 or +1 depending on the sign of "a - b".
 */
static gint version_tagcmp(guchar a, guchar b)
{
	if (a == b)
		return 0;

	if (a == '\0')			/* Stable release has no tag */
		return +1;

	if (b == '\0')			/* Stable release has no tag */
		return -1;

	if (a == 'u')			/* Unstable from CVS */
		return -1;

	if (b == 'u')			/* Unstable from CVS */
		return +1;

	return a < b ? -1 : +1;	/* 'a' or 'b' for Alpha / Beta */
}

/*
 * version_cmp
 *
 * Compare two gtk-gnutella versions, timestamp not withstanding.
 * Returns -1, 0 or +1 depending on the sign of "a - b".
 */
gint version_cmp(const version_t *a, const version_t *b)
{
	if (a->major == b->major) {
		if (a->minor == b->minor) {
			if (a->patchlevel == b->patchlevel) {
				if (0 == version_tagcmp(a->tag, b->tag)) {
					if (a->taglevel == b->taglevel)
						return 0;
					return a->taglevel < b->taglevel ? -1 : +1;
				}
				return version_tagcmp(a->tag, b->tag);
			}
			return a->patchlevel < b->patchlevel ? -1 : +1;
		}
		return a->minor < b->minor ? -1 : +1;
	}
	return a->major < b->major ? -1 : +1;
}

/*
 * version_fill
 *
 * Parse vendor string and fill supplied version structure `vs'.
 * Returns OK if we were able to parse correctly.
 */
gboolean version_fill(const gchar *version, version_t *vs)
{
	if (!version_parse(version, vs))
		return FALSE;

	version_stamp(version, vs);			/* Optional, set to 0 if missing */

	return TRUE;
}

static void version_new_found(const gchar *text, gboolean stable)
{
    static gchar last_stable[256] = "";
    static gchar last_dev[256] = "";
    gchar *s;

    if (stable)
        gm_snprintf(last_stable, sizeof(last_stable), "%s", text);
    else
        gm_snprintf(last_dev, sizeof(last_dev), "%s", text);

	s = g_strdup_printf(
		"%s - Newer version%s available: %s%s%s%s%s",
		GTA_WEBSITE,
		last_stable[0] && last_dev[0] ? "s" : "",
		last_stable[0] ? "release " : "",
		last_stable[0] ? last_stable : "",
		last_stable[0] && last_dev[0] ? " / " : "",
		last_dev[0] ? "from CVS " : "",
		last_dev[0] ? last_dev : "");

    gnet_prop_set_string(PROP_NEW_VERSION_STR, s);

    g_free(s);
}

/*
 * version_check
 *
 * Check version of servent, and if it's a gtk-gnutella more recent than we
 * are, record that fact and change the status bar.
 *
 * Returns TRUE if we properly checked the version, FALSE if we got something
 * looking as gtk-gnutella but which failed the token-based sanity checks.
 */
gboolean version_check(const guchar *str, const gchar *token)
{
	version_t their_version;
	version_t *target_version;
	gint cmp;
	const gchar *version;

	if (!version_parse(str, &their_version))
		return TRUE;			/* Not gtk-gnutella, or unparseable */

	/*
	 * Is their version a development one, or a release?
	 */

	if (their_version.tag == 'u')
		target_version = &last_dev_version;
	else
		target_version = &last_rel_version;

	cmp = version_cmp(target_version, &their_version);

	if (dbg > 6)
		version_dump(str, &their_version,
			cmp == 0 ? "=" :
			cmp > 0 ? "-" : "+");

	/*
	 * Check timestamp.
	 */

	version_stamp(str, &their_version);

	if (dbg > 6)
		printf("VERSION time=%d\n", (gint) their_version.timestamp);

	/*
	 * If version claims something older than TOKEN_START_DATE, then
	 * there must be a token present.
	 */

	if (their_version.timestamp >= TOKEN_START_DATE) {
		tok_error_t error;

		if (token == NULL) {
			g_warning("got GTKG vendor string \"%s\" without token!", str);
			return FALSE;	/* Can't be correct */
		}

		error = tok_version_valid(str, token, strlen(token));

		if (error != TOK_OK) {
			g_warning("vendor string \"%s\" has wrong token \"%s\": %s ",
				str, token, tok_strerror(error));
			return FALSE;
		}

		/*
		 * OK, so now we know we can "trust" this version string as being
		 * probably genuine.  It makes sense to extract version information
		 * out of it.
		 */
	}

	if (cmp > 0)			/* We're more recent */
		return TRUE;

	/*
	 * If timestamp is greater and we were comparing against a stable
	 * release, and cmp == 0, then this means an update in CVS about
	 * a "released" version, probably alpha/beta.
	 */

	if (
		cmp == 0 &&
		their_version.timestamp > target_version->timestamp &&
		target_version == &last_rel_version
	) {
		if (dbg > 6)
			printf("VERSION is a CVS update of a release\n");

		if (version_cmp(&last_dev_version, &their_version) > 0) {
			if (dbg > 6)
				printf("VERSION is less recent than latest dev we know\n");
			return TRUE;
		}
		target_version = &last_dev_version;
	}

	if (their_version.timestamp <= target_version->timestamp)
		return TRUE;

	if (their_version.timestamp == our_version.timestamp)
		return TRUE;

	/*
	 * We found a more recent version than the last version seen.
	 */

	if (dbg > 4)
		printf("more recent %s VERSION \"%s\"\n",
			target_version == &last_dev_version ? "dev" : "rel", str);

	*target_version = their_version;		/* struct copy */

	/*
	 * Signal new version to user.
	 *
	 * Unless they run a development version, don't signal development
	 * updates to them: they're probably not interested.
	 */

	version =  version_str(&their_version);

	g_warning("more recent %s version of gtk-gnutella: %s",
		target_version == &last_dev_version ? "development" : "released",
		version);

	if (target_version == &last_rel_version)
		version_new_found(version, TRUE);
	else if (our_version.tag == 'u')
		version_new_found(version, FALSE);

	return TRUE;
}
 
/*
 * version_init
 *
 * Initialize version string.
 */
void version_init(void)
{
	struct utsname un;
	gchar buf[128];
	gboolean ok;
	gchar patch[80];

#ifdef GTA_PATCHLEVEL
	if (GTA_PATCHLEVEL)
		gm_snprintf(patch, sizeof(patch), ".%u", GTA_PATCHLEVEL);
	else
		patch[0] = '\0';
#else
	patch[0] = '\0';
#endif

	(void) uname(&un);

	gm_snprintf(buf, sizeof(buf) - 1,
		"%u.%u%s%s", GTA_VERSION, GTA_SUBVERSION, patch, GTA_REVCHAR);

	version_number = atom_str_get(buf);

	gm_snprintf(buf, sizeof(buf) - 1,
		"gtk-gnutella/%s (%s; %s; %s %s %s)",
		version_number, GTA_RELEASE, GTA_INTERFACE,
		un.sysname, un.release, un.machine);

	version_string = atom_str_get(buf);

	ok = version_parse(version_string, &our_version);
	g_assert(ok);

	version_stamp(version_string, &our_version);
	g_assert(our_version.timestamp > 0);

	last_rel_version = our_version;		/* struct copy */
	last_dev_version = our_version;		/* struct copy */
}

/*
 * version_ancient_warn
 *
 * Called after GUI initialized to warn them about an ancient version.
 * (over a year old).
 *
 * If the version being ran is not a stable one, warn after 60 days.
 */
void version_ancient_warn(void)
{
	g_assert(our_version.timestamp > 0);	/* version_init() called */

	if (time(NULL) - our_version.timestamp > VERSION_ANCIENT_WARN) {
		g_warning("version of gtk-gnutella is too old, you should upgrade!");
        gnet_prop_set_boolean_val(PROP_ANCIENT_VERSION, TRUE);
	}

	if (
		our_version.tag &&
		time(NULL) - our_version.timestamp > VERSION_UNSTABLE_WARN
	) {
		g_warning("unstable version of gtk-gnutella is aging, please upgrade!");
        gnet_prop_set_boolean_val(PROP_ANCIENT_VERSION, TRUE);
	}
}

/*
 * version_is_too_old
 *
 * Check the timestamp in the GTKG version string and returns TRUE if it
 * is too old or could not be parsed, FALSE if OK.
 */
gboolean version_is_too_old(const gchar *vendor)
{
	version_t ver;
	time_t now = time(NULL);

	version_stamp(vendor, &ver);		/* Fills ver->timestamp */

	if (now - ver.timestamp > VERSION_ANCIENT_BAN)
		return TRUE;

	if (!version_parse(vendor, &ver))	/* Fills ver->tag */
		return TRUE;					/* Unable to parse */

	if (ver.tag && now - ver.timestamp > VERSION_UNSTABLE_BAN)
		return TRUE;

	return FALSE;
}

/*
 * version_close
 *
 * Free version string.
 */
void version_close(void)
{
	atom_str_free(version_number);
	atom_str_free(version_string);

	if (version_cmp(&our_version, &last_rel_version) < 0)
		g_warning("upgrade recommended: most recent released version seen: %s",
			version_str(&last_rel_version));
	else if (version_cmp(&our_version, &last_dev_version) < 0)
		g_warning("upgrade possible: most recent development version seen: %s",
			version_str(&last_dev_version));
}

