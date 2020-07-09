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
 *      51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *----------------------------------------------------------------------
 */

/**
 * @ingroup lib
 * @file
 *
 * Records and gives back product information.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#ifndef _product_h_
#define _product_h_

/*
 * Public interface.
 */

void product_init(const char *name,
	uint8 major, uint8 minor, uint8 patchlevel, const char *revchar,
	const char *date, const char *version, const char *revision,
	const char *build);

const char *product_name(void) G_PURE;
bool product_has_forced_name(void) G_PURE;
const char *product_nickname(void) G_PURE;
const char *product_date(void) G_PURE;
const char *product_version(void) G_PURE;
uint8 product_major(void) G_PURE;
uint8 product_minor(void) G_PURE;
uint8 product_revchar(void) G_PURE;
const char *product_revision(void) G_PURE;
uint8 product_patchlevel(void) G_PURE;
const char *product_build_full(void);
const char *product_interface(void);
const char *product_website(void);
uint32 product_build(void);

void product_set_forced_name(const char *name);
void product_set_nickname(const char *nickname);
void product_set_interface(const char *iface);
void product_set_website(const char *web);

#endif /* _product_h_ */

/* vi: set ts=4 sw=4 cindent: */
