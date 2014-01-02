/*
 * Copyright (c) 2012, Raphael Manfredi
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
 * G2 packet framing.
 *
 * @author Raphael Manfredi
 * @date 2012
 */

#ifndef _core_g2_frame_h_
#define _core_g2_frame_h_

#define G2_FRAME_NAME_LEN_MAX	8			/**< Maximum length of a packet */
#define G2_FRAME_CF				(1U << 2)	/**< The CF flag */
#define G2_FRAME_BE				(1U << 1)	/**< The BE flag */

/*
 * Public interface.
 */

struct g2_tree;

size_t g2_frame_serialize(const struct g2_tree *root, void *dest, size_t len);
const struct g2_tree *g2_frame_deserialize(const void *buf,
	size_t len, size_t *packet_len, bool copy);
size_t g2_frame_whole_length(const void *buf, size_t len);

#endif /* _core_g2_frame_h_ */

