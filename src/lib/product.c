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

static struct product_info {
	const char *p_name;
	const char *p_nickname;
	const char *p_date;
	const char *p_version;
	const char *p_build;
	const char *p_revision;
	const char *p_interface;
	const char *p_website;
	const char *p_revchar;
	uint8 p_major;
	uint8 p_minor;
	uint8 p_patchlevel;
} product_info;

/**
 * Get the product's name.
 */
const char *
product_name(void)
{
	return product_info.p_name;
}

/**
 * Get the product's nickname.
 *
 * If no nickname was registered, use the product's name.
 */
const char *
product_nickname(void)
{
	if (product_info.p_nickname != NULL)
		return product_info.p_nickname;

	return product_info.p_name;
}

/**
 * Set the product's nickname, hopefully a shorter name than the name itself.
 */
void
product_set_nickname(const char *name)
{
	product_info.p_nickname = name;
}

/**
 * Get version date string, as an ISO string.
 */
const char *
product_date(void)
{
	return product_info.p_date;
}

/**
 * Get version string, a combination of major/minor/patchlevel and revchar.
 */
const char *
product_version(void)
{
	return product_info.p_version;
}

/**
 * Get major version.
 */
uint8
product_major(void)
{
	return product_info.p_major;
}

/**
 * Get minor version.
 */
uint8
product_minor(void)
{
	return product_info.p_minor;
}

/**
 * Get revision character.
 */
uint8
product_revchar(void)
{
	return (uint8) product_info.p_revchar[0];
}

/**
 * Get revision string.
 */
const char *
product_revision(void)
{
	return NULL == product_info.p_revision ? "" : product_info.p_revision;
}

/**
 * Get revision patchlevel.
 */
uint8
product_patchlevel(void)
{
	return product_info.p_patchlevel;
}

/**
 * Set product interface.
 */
void
product_set_interface(const char *iface)
{
	product_info.p_interface = iface;
}

/**
 * Get the product's interface.
 */
const char *
product_interface(void)
{
	return NULL == product_info.p_interface ? "None" : product_info.p_interface;
}

/**
 * Set product's web site.
 */
void
product_set_website(const char *website)
{
	product_info.p_website = website;
}

/**
 * Get the product's web site.
 */
const char *
product_website(void)
{
	return NULL == product_info.p_website ? "" : product_info.p_website;
}

/**
 * Get build number.
 */
uint32
product_build(void)
{
	static uint32 build;
	static bool initialized;

	if G_UNLIKELY(!initialized) {
		const char *p;

		initialized = TRUE;
		p = is_strprefix(product_info.p_build, "$Revision: ");
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
product_build_full(void)
{
	static const char *result;

	if G_UNLIKELY(NULL == result) {
		const char *p;
		p = is_strprefix(product_info.p_build, "$Revision: ");
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

			result = ostrdup_readonly(tmp);
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
void G_COLD
product_init(const char *name,
	uint8 major, uint8 minor, uint8 patchlevel, const char *revchar,
	const char *date, const char *version, const char *revision,
	const char *build)
{
	product_info.p_name = name;
	product_info.p_major = major;
	product_info.p_minor = minor;
	product_info.p_patchlevel = patchlevel;
	product_info.p_revchar = revchar;
	product_info.p_date = date;
	product_info.p_version = version;
	product_info.p_revision = revision;
	product_info.p_build = build;
}

/* vi: set ts=4 sw=4 cindent: */
