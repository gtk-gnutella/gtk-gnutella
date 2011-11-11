/*
 * Copyright (c) 2011, Raphael Manfredi
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
 * Records and gives back product information.
 *
 * The aim is to limit dependency on product-specific includes and store
 * in a single place all these information.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#include "common.h"

#include "product.h"
#include "halloc.h"
#include "glib-missing.h"
#include "misc.h"
#include "omalloc.h"
#include "parse.h"

#include "override.h"		/* Must be the last header included */

static const char *product_name;
static const char *product_date;
static const char *product_version;
static const char *product_build;
static const char *product_revision;
static const char *product_interface;
static const char *product_website;
static guint8 product_major;
static guint8 product_minor;
static const char *product_revchar;
static guint8 product_patchlevel;

/**
 * Get the product's name.
 */
const char *
product_get_name(void)
{
	return product_name;
}

/**
 * Get version date string, as an ISO string.
 */
const char *
product_get_date(void)
{
	return product_date;
}

/**
 * Get version string, a combination of major/minor/patchlevel and revchar.
 */
const char *
product_get_version(void)
{
	return product_version;
}

/**
 * Get major version.
 */
guint8
product_get_major(void)
{
	return product_major;
}

/**
 * Get minor version.
 */
guint8
product_get_minor(void)
{
	return product_minor;
}

/**
 * Get revision character.
 */
guint8
product_get_revchar(void)
{
	return (guint8) product_revchar[0];
}

/**
 * Get revision string.
 */
const char *
product_get_revision(void)
{
	return NULL == product_revision ? "" : product_revision;
}

/**
 * Get revision patchlevel.
 */
guint8
product_get_patchlevel(void)
{
	return product_patchlevel;
}

/**
 * Set product interface.
 */
void
product_set_interface(const char *interface)
{
	product_interface = interface;
}

/**
 * Get the product's interface.
 */
const char *
product_get_interface(void)
{
	return NULL == product_interface ? "None" : product_interface;
}

/**
 * Set product's web site.
 */
void
product_set_website(const char *website)
{
	product_website = website;
}

/**
 * Get the product's web site.
 */
const char *
product_get_website(void)
{
	return NULL == product_website ? "" : product_website;
}

/**
 * Get build number.
 */
guint32
product_get_build(void)
{
	static guint32 build;
	static gboolean initialized;

	if G_UNLIKELY(!initialized) {
		const char *p;

		initialized = TRUE;
		p = is_strprefix(product_build, "$Revision: ");
		if (p) {
			int error;
			build = parse_uint32(p, NULL, 10, &error);
		}
	}
	return build;
}

/**
 * Get full build number string.
 */
const char *
product_get_build_full(void)
{
	static char *result;

	if G_UNLIKELY(NULL == result) {
		const char *p;
		p = is_strprefix(product_build, "$Revision: ");
		if (p != NULL) {
			char *tmp;
			char *q;
			size_t len = strlen(p) + 2;		/* Leading '-', trailing NUL */

			tmp = halloc(len);
			g_strlcpy(tmp + 1, p, len - 1);
			*tmp = '-';
			q = strchr(tmp, ' ');
			if (q != NULL)
				*q = '\0';		/* Truncate at first space */

			result = ostrdup(tmp);
			HFREE_NULL(tmp);
		} else {
			result = "";		/* No change since last git tag */
		}
	}

	return result;
}

/*
 * Initialize product information.
 */
G_GNUC_COLD void
product_init(const char *name,
	guint8 major, guint8 minor, guint8 patchlevel, const char *revchar,
	const char *date, const char *version, const char *revision,
	const char *build)
{
	product_name = name;
	product_major = major;
	product_minor = minor;
	product_patchlevel = patchlevel;
	product_revchar = revchar;
	product_date = date;
	product_version = version;
	product_revision = revision;
	product_build = build;
}
 
/* vi: set ts=4 sw=4 cindent: */
