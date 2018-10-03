/*
 * Copyright (c) 2018 Raphael Manfredi
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
 * ANSI color codes.
 *
 * @author Raphael Manfredi
 * @date 2018
 */

#ifndef _color_h_
#define _color_h_

/*
 * Public interface.
 */

const char *color_reset(void);
const char *color_inverse(bool on);
const char *color_underline(bool on);
const char *color_blink(bool on);
const char *color_escape(const char *spec, bool silent);
const char *color_decompile(const char *esc);

void color_manual(void);

#endif /* _color_h_ */

/* vi: set ts=4 sw=4 cindent: */
