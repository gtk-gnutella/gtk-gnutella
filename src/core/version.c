/*
 * $Id$
 *
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
 * Version management.
 *
 * @author Raphael Manfredi
 * @date 2002-2003
 */

#include "common.h"

RCSID("$Id$")

#ifdef I_SYS_UTSNAME
#include <sys/utsname.h>		/* For uname() */
#endif

#include "version.h"
#include "token.h"
#include "settings.h"

#include "if/gnet_property.h"
#include "if/gnet_property_priv.h"

#include "if/core/main.h"

#include "lib/atoms.h"
#include "lib/getdate.h"
#include "lib/misc.h"
#include "lib/glib-missing.h"
#include "lib/tm.h"
#include "lib/utf8.h"
#include "lib/override.h"		/* Must be the last header included */

#define SECS_PER_DAY	86400

gchar *version_string = NULL;
gchar *version_short_string = NULL;

static version_t our_version;
static version_t last_rel_version;
static version_t last_dev_version;
static guint8 version_code;

/**
 * Get version string.
 */
const gchar *
version_get_string(void)
{
	return version_string;
}

/**
 * Get version code (year/month coded in one byte).
 */
guint8
version_get_code(void)
{
	return version_code;
}

/**
 * Dump original version string and decompiled form to stdout.
 */
static void
version_dump(const gchar *str, const version_t *ver, const gchar *cmptag)
{
	printf("VERSION%s \"%s\":\n"
		"\tmajor=%u minor=%u patch=%u tag=%c taglevel=%u build=%u\n",
		cmptag, str, ver->major, ver->minor, ver->patchlevel,
		ver->tag ? ver->tag : ' ', ver->taglevel, ver->build);
}

/**
 * @return a user-friendly description of the version.
 * NB: returns pointer to static data.
 */
const gchar *
version_str(const version_t *ver)
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

	if (ver->build)
		rw += gm_snprintf(&str[rw], sizeof(str)-rw, "-%u", ver->build);

	if (ver->timestamp) {
		struct tm *tmp = localtime(&ver->timestamp);
		rw += gm_snprintf(&str[rw], sizeof(str)-rw, " (%d-%02d-%02d)",
			tmp->tm_year + 1900, tmp->tm_mon + 1, tmp->tm_mday);
	}

	return str;
}

/**
 * Parse gtk-gnutella's version number in User-Agent/Server string `str'
 * and extract timestamp into `ver'.
 */
static void
version_stamp(const gchar *str, version_t *ver)
{
	static gchar stamp[256];
	const gchar *p;

	ver->timestamp = 0;

	/*
	 * A typical vendor string with a timestamp would look like:
	 *
	 *    gtk-gnutella/0.85 (04/04/2002; X11; FreeBSD 4.6-STABLE i386)
	 *
	 * The date stamp is formattted as DD/MM/YYYY here, but the date2time()
	 * routine is also able to parse the ISO format YYYY-MM-DD which is
	 * being used starting 2004-03-02.
	 */

	p = strchr(str, '(');
	if (p) {
		const gchar *end;

		p++;
		end = strchr(p, ';');
		if (end == NULL)
			end = strchr(p, ')');		/* Only date present: short version */
		if (end) {
			size_t size = end - p + 1;

			/*
			 * Using date2time() will allow us to possibly change the date
			 * format in the future, without impacting the ability of older
			 * servents to parse it.
			 */

			g_strlcpy(stamp, p, MIN(size, sizeof(stamp)));
			ver->timestamp = date2time(stamp, tm_time());

			if (ver->timestamp == -1) {
				ver->timestamp = 0;
				g_warning("could not parse timestamp \"%s\" in \"%s\"", p, str);
			}
		} else
			g_warning("no timestamp in \"%s\"", str);
	}
}


/**
 * Parse gtk-gnutella's version number in User-Agent/Server string `str'
 * and extract relevant information into `ver'.
 *
 * @returns TRUE if we parsed a gtk-gnutella version correctly, FALSE if we
 * were not facing a gtk-gnutella version, or if we did not recognize it.
 */
static gboolean
version_parse(const gchar *str, version_t *ver)
{
	const gchar *v;
	gint error;

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
	 *
	 * Starting 2006-08-26, the user-agent string includes the SVN revision
	 * at the time of the build.  To be compatible with the servents out
	 * there, the version is included as an optional tag following the date.
	 *
	 *    gtk-gnutella/0.85 (04/04/2002; r3404; X11; FreeBSD 4.6-STABLE i386)
	 *
	 * However, we also start parsing the new format that we shall use when
	 * all current GTKG out there have expired:
	 *
	 *    gtk-gnutella/0.85-3404 (04/04/2002; X11; FreeBSD 4.6-STABLE i386)
	 *    gtk-gnutella/0.90b2-3404 (04/04/2002; X11; FreeBSD 4.6-STABLE i386)
	 *
	 * where the '-3404' introduces the build number.
	 */

	if (NULL == (v = is_strprefix(str, "gtk-gnutella/")))
		return FALSE;

	/*
	 * Parse "major.minor", followed by optional ".patchlevel".
	 */

	ver->major = parse_uint32(v, &v, 10, &error);
	if (error)
		return FALSE;

	if (*v++ != '.')
		return FALSE;

	ver->minor = parse_uint32(v, &v, 10, &error);
	if (error)
		return FALSE;

	if ('.' == *v) {
		v++;
		ver->patchlevel = parse_uint32(v, &v, 10, &error);
		if (error)
			return FALSE;
	} else
		ver->patchlevel = 0;

	/*
	 * Parse optional tag letter "x" followed by optional "taglevel".
	 */

	if (is_ascii_alpha(*v)) {
		ver->tag = *v++;
		if (is_ascii_digit(*v)) {
			ver->taglevel = parse_uint32(v, &v, 10, &error);
			if (error)
				return FALSE;
		} else
			ver->taglevel = 0;
	} else {
		ver->tag = '\0';
		ver->taglevel = 0;
	}

	/*
	 * Parse optional "-build".
	 */

	if ('-' == *v) {
		v++;
		ver->build = parse_uint32(v, &v, 10, &error);
		if (error)
			return FALSE;
	} else
		ver->build = 0;

	/*
	 * Legacy support: until 2007-03-22, we look at the build revision
	 * number in the user-agent string if we did not get it so far.
	 * We expect to find something like "(2006-02-22; r3456"
	 *
	 * Remove this code after 2007-03-22!
	 */

	if (0 == ver->build) {	/* Useless after 2007-03-22 normally */
		const gchar *p;

		p = strchr(str, '(');		/* ')' for vi */
		if (p)
			p = strchr(p, ';');		/* Move past date */

		if (p && NULL != (p = is_strprefix(p, "; r")))
			ver->build = (guint32) atoi(p);
	}

	if (dbg > 6)
		version_dump(str, ver, "#");

	return TRUE;
}

/**
 * Compare two tag chars, assuming version numbers are equal.
 * @returns -1, 0 or +1 depending on the sign of "a - b".
 */
static gint
version_tagcmp(guchar a, guchar b)
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

/**
 * Compare two gtk-gnutella versions, timestamp not withstanding.
 * @returns -1, 0 or +1 depending on the sign of "a - b".
 */
gint
version_cmp(const version_t *a, const version_t *b)
{
	if (a->major == b->major) {
		if (a->minor == b->minor) {
			if (a->patchlevel == b->patchlevel) {
				if (0 == version_tagcmp(a->tag, b->tag)) {
					if (a->taglevel == b->taglevel) {
						if (a->build == b->build)
							return 0;
						return a->build < b->build ? -1 : +1;
					}
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

/**
 * Parse vendor string and fill supplied version structure `vs'.
 *
 * @returns OK if we were able to parse correctly.
 */
gboolean
version_fill(const gchar *version, version_t *vs)
{
	if (!version_parse(version, vs))
		return FALSE;

	version_stamp(version, vs);			/* Optional, set to 0 if missing */

	return TRUE;
}

/**
 * Invoked when a newer version is found.
 */
static void
version_new_found(const gchar *text, gboolean stable)
{
    static gchar last_stable[256] = "";
    static gchar last_dev[256] = "";
	gchar s[1024];

    if (stable)
        utf8_strlcpy(last_stable, text, sizeof last_stable);
    else
        utf8_strlcpy(last_dev, text, sizeof last_dev);

	if ('\0' != last_stable[0] && '\0' != last_dev[0]) {
		gm_snprintf(s, sizeof s,
			_(" - Newer versions available: release %s / from CVS %s"),
			last_stable, last_dev);
	} else if ('\0' != last_stable[0]) {
		gm_snprintf(s, sizeof s,
			_(" - Newer version available: release %s"),
			last_stable);
	} else if ('\0' != last_dev[0]) {
		gm_snprintf(s, sizeof s,
			_(" - Newer version available: from CVS %s"),
			last_dev);
	}

    gnet_prop_set_string(PROP_NEW_VERSION_STR, s);
}

/**
 * Check version of servent, and if it's a gtk-gnutella more recent than we
 * are, record that fact and change the status bar.
 *
 * The `addr' is being passed solely for the tok_version_valid() call.
 *
 * @returns TRUE if we properly checked the version, FALSE if we got something
 * looking as gtk-gnutella but which failed the token-based sanity checks.
 */
gboolean
version_check(const gchar *str, const gchar *token, const host_addr_t addr)
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

	if (delta_time(their_version.timestamp, 0) >= TOKEN_START_DATE) {
		tok_error_t error;

		if (token == NULL) {
            if (dbg) {
                g_message("got GTKG vendor string \"%s\" without token!", str);
            }
			return FALSE;	/* Can't be correct */
		}

		error = tok_version_valid(str, token, strlen(token), addr);

		/*
		 * Unfortunately, if our token has expired, we can no longer
		 * validate the tokens of the remote peers, since they are using
		 * a different set of keys.
		 *
		 * This means an expired GTKG will blindly trust well-formed remote
		 * tokens at face value.  But it's their fault, they should not run
		 * an expired version!
		 *		--RAM, 2005-12-21
		 */

		if (error == TOK_BAD_KEYS && tok_is_ancient(tm_time()))
			error = TOK_OK;		/* Our keys have expired, cannot validate */

		if (error != TOK_OK) {
            if (dbg) {
                g_message("vendor string \"%s\" [%s] has wrong token "
                    "\"%s\": %s ", str, host_addr_to_string(addr), token,
                    tok_strerror(error));
            }
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
		delta_time(their_version.timestamp, target_version->timestamp) > 0 &&
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

	/*
	 * Only compare a development version which has the same version
	 * number with a more up to date version.
	 * This will also avoid a 0.93.4u to be listed out of date if also a 0.94u
	 * is available, while both are actually in development.
	 * 		-- JA 15/04/2004
	 */

	/*
	 * Their version is more recent, but is unstable
	 */
	if (their_version.tag == 'u' && cmp < 0)
		return TRUE;

	if (delta_time(their_version.timestamp, target_version->timestamp) <= 0)
		return TRUE;

	if (delta_time(their_version.timestamp, our_version.timestamp) == 0)
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

	g_message("more recent %s version of gtk-gnutella: %s",
		target_version == &last_dev_version ? "development" : "released",
		version);

	if (target_version == &last_rel_version)
		version_new_found(version, TRUE);
	else if (our_version.tag == 'u')
		version_new_found(version, FALSE);

	return TRUE;
}

/**
 * Initialize version string.
 */
void
version_init(void)
{
	gchar buf[128];
	time_t now = tm_time();
	const gchar *sysname = "Unknown";
	const gchar *machine = NULL;
	gboolean ok;

#ifdef HAS_UNAME
	{
		static struct utsname un;	/* Must survive this scope */
	
		if (-1 != uname(&un)) {
			sysname = un.sysname;
			machine = un.machine;
		} else {
			g_warning("uname() failed: %s:", g_strerror(errno));
		}
	}
#endif /* HAS_UNAME */

	/*
	 * Until 2007-03-22, we generate the version string using "r<build#>"
	 * in the optional part.  After that date, the revision format is
	 * expanded to include the build number right into the string.
	 */

	if (now <= 1174518000)				/* before 2007-03-22 */
		gm_snprintf(buf, sizeof buf,
			"gtk-gnutella/%s (%s; r%u; %s; %s%s%s)",
			GTA_VERSION_NUMBER, GTA_RELEASE, main_get_build(),
			GTA_INTERFACE,
			sysname,
			machine && machine[0] ? " " : "",
			machine ? machine : "");
	else								/* after 2007-03-22 */
		gm_snprintf(buf, sizeof buf,
			"gtk-gnutella/%s-%u (%s; %s; %s%s%s)",
			GTA_VERSION_NUMBER, main_get_build(),
			GTA_RELEASE, GTA_INTERFACE,
			sysname,
			machine && machine[0] ? " " : "",
			machine ? machine : "");

	version_string = atom_str_get(buf);
	ok = version_parse(version_string, &our_version);
	g_assert(ok);

	g_message("%s", version_string);

	version_stamp(version_string, &our_version);
	g_assert(our_version.timestamp != 0);

	if (now <= 1174518000)				/* before 2007-03-22 */
		gm_snprintf(buf, sizeof(buf),
			"gtk-gnutella/%s (%s; r%u)",
			GTA_VERSION_NUMBER, GTA_RELEASE, main_get_build());
	else
		gm_snprintf(buf, sizeof(buf),
			"gtk-gnutella/%s-%u (%s)",
			GTA_VERSION_NUMBER, main_get_build(), GTA_RELEASE);

	version_short_string = atom_str_get(buf);

	last_rel_version = our_version;		/* struct copy */
	last_dev_version = our_version;		/* struct copy */

	/*
	 * The version code is a one-byte encoding of the year/month, since
	 * what matters is not much the version number as to the age of the
	 * servent...  The version code is transmitted in pongs via GGEP "VC".
	 */

	if (our_version.timestamp) {
		struct tm *tmp = localtime(&our_version.timestamp);
		version_code =
			(((tmp->tm_year + 1900 - 2000) & 0x0f) << 4) | (tmp->tm_mon + 1);
	} else
		version_code = 0;

	/*
	 * The property system is not up when this is called, but we need
	 * to set this variable correctly.
	 */

	if (
		tok_is_ancient(now) ||
		delta_time(now, our_version.timestamp) > VERSION_ANCIENT_WARN ||
		(our_version.tag &&
			delta_time(now, our_version.timestamp) > VERSION_UNSTABLE_WARN)
	)
		*(guint32 *) &ancient_version = TRUE;
}

/**
 * Called when the version has expired since the indicated amount.
 * If that amount is greater than our grace period, refuse to run unless
 * they set the "ancient_version_force" property explicitly.
 */
static void
version_maybe_refuse(gint overtime)
{
	gchar *force;
	property_t prop = PROP_ANCIENT_VERSION_FORCE;

	if (overtime < VERSION_ANCIENT_GRACE)
		return;

	force = gnet_prop_get_string(prop, NULL, 0);

	if (0 == strcmp(force, version_string)) {
		G_FREE_NULL(force);
		return;
	}

	/*
	 * Sorry, they must explicitly allow us to run, we're too ancient.
	 */

	settings_ask_for_property(gnet_prop_name(prop), version_string);

	/* NOTREACHED */
}

/**
 * Called after GUI initialized to warn them about an ancient version.
 * (over a year old).
 *
 * If the version being ran is not a stable one, warn after 60 days, otherwise
 * warn after a year.  If we're not "expired" yet but are approaching the
 * deadline, start to remind them.  After the deadline plus some grace period,
 * refuse to run unless a special property is set.
 */
void
version_ancient_warn(void)
{
	time_t now = tm_time();
	gint lifetime, remain, elapsed;
	time_t s;

	g_assert(our_version.timestamp != 0);	/* version_init() called */

	/*
	 * Must reset the property to FALSE so that if it changes and becomes
	 * TRUE, then the necessary GUI callbacks will get triggered.  Indeed,
	 * setting a property to its ancient value is not considered a change,
	 * and rightfully so!
	 */

	gnet_prop_set_boolean_val(PROP_ANCIENT_VERSION, FALSE);

	elapsed = delta_time(now, our_version.timestamp);

	if (elapsed > VERSION_ANCIENT_WARN || tok_is_ancient(now)) {
		version_maybe_refuse(elapsed - VERSION_ANCIENT_WARN);
		g_warning("version of gtk-gnutella is too old, you should upgrade!");
        gnet_prop_set_boolean_val(PROP_ANCIENT_VERSION, TRUE);
		return;
	}

	if (our_version.tag && elapsed > VERSION_UNSTABLE_WARN) {
		version_maybe_refuse(elapsed - VERSION_UNSTABLE_WARN);
		g_warning("unstable version of gtk-gnutella is aging, please upgrade!");
        gnet_prop_set_boolean_val(PROP_ANCIENT_VERSION, TRUE);
		return;
	}

	/*
	 * Check whether we're nearing ancient version status, to warn them
	 * beforehand that the version will become old soon.
	 */

	lifetime = our_version.tag ? VERSION_UNSTABLE_WARN : VERSION_ANCIENT_WARN;
	remain = lifetime - elapsed;

	g_assert(remain >= 0);		/* None of the checks above have fired */

	/*
	 * Try to see whether the token will expire within the next
	 * VERSION_ANCIENT_REMIND secs, looking for the minimum cutoff date.
	 *
	 * Indeed, it is possible to emit new versions without issuing a
	 * new set of token keys, thereby constraining the lifetime of the
	 * version.  This is usually what happens for bug-fixing releases
	 * that do not introduce significant Gnutella features.
	 */

	for (s = now + VERSION_ANCIENT_REMIND; s > now; s -= SECS_PER_DAY) {
		if (!tok_is_ancient(s))
			break;
	}

	remain = MIN(remain, s - now);

	/*
	 * Let them know when version will expire soon...
	 */

	if (remain < VERSION_ANCIENT_REMIND)
        gnet_prop_set_guint32_val(PROP_ANCIENT_VERSION_LEFT_DAYS,
			remain / SECS_PER_DAY);
}

/**
 * Check the timestamp in the GTKG version string and returns TRUE if it
 * is too old or could not be parsed, FALSE if OK.
 */
gboolean
version_is_too_old(const gchar *vendor)
{
	version_t ver;
	time_t now = tm_time();
	gint d;

	version_stamp(vendor, &ver);		/* Fills ver->timestamp */
	d = delta_time(now, ver.timestamp);
	if (d > VERSION_ANCIENT_BAN)
		return TRUE;

	if (!version_parse(vendor, &ver))	/* Fills ver->tag */
		return TRUE;					/* Unable to parse */

	if (ver.tag && d > VERSION_UNSTABLE_BAN)
		return TRUE;

	return FALSE;
}

/**
 * Free version string.
 */
void
version_close(void)
{
	atom_str_free(version_string);
	version_string = NULL;
	atom_str_free(version_short_string);
	version_short_string = NULL;

	if (version_cmp(&our_version, &last_rel_version) < 0)
		g_warning("upgrade recommended: most recent released version seen: %s",
			version_str(&last_rel_version));
	else if (version_cmp(&our_version, &last_dev_version) < 0)
		g_warning("upgrade possible: most recent development version seen: %s",
			version_str(&last_dev_version));
}

/* vi: set ts=4 sw=4 cindent: */
