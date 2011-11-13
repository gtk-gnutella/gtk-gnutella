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
 * @author Raphael Manfredi
 * @date 2011
 */

#ifndef _product_h_
#define _product_h_

/*
 * Public interface.
 */

void product_init(const char *name,
	guint8 major, guint8 minor, guint8 patchlevel, const char *revchar,
	const char *date, const char *version, const char *revision,
	const char *build);

const char *product_get_name(void) G_GNUC_PURE;
const char *product_get_date(void) G_GNUC_PURE;
const char *product_get_version(void) G_GNUC_PURE;
guint8 product_get_major(void) G_GNUC_PURE;
guint8 product_get_minor(void) G_GNUC_PURE;
guint8 product_get_revchar(void) G_GNUC_PURE;
const char *product_get_revision(void) G_GNUC_PURE;
guint8 product_get_patchlevel(void) G_GNUC_PURE;
guint32 product_get_build(void);
const char *product_get_build_full(void);

<<<<<<< HEAD
<<<<<<< HEAD
void product_set_interface(const char *iface);
=======
void product_set_interface(const char *interface);
>>>>>>> alloc-rate
=======
void product_set_interface(const char *interface);
>>>>>>> parq-bug
const char *product_get_interface(void);
void product_set_website(const char *web);
const char *product_get_website(void);

#endif /* _product_h_ */

/* vi: set ts=4 sw=4 cindent: */
