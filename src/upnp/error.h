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
 * @ingroup upnp
 * @file
 *
 * UPnP known error codes.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#ifndef _upnp_error_h_
#define _upnp_error_h_

/*
 * Explicitly handled error conditions
 */

#define UPNP_ERR_OK						0
#define UPNP_ERR_UNPARSEABLE			1
#define UPNP_ERR_SOAP					2
#define UPNP_ERR_BAD_REPLY				3		

#define UPNP_ERR_INVALID_ACTION			401
#define UPNP_ERR_UNAUTHORIZED			606
#define UPNP_ERR_ONLY_PERMANENT_LEASE	725

/*
 * Public interface.
 */

const char *upnp_strerror(int code);

#endif /* _upnp_error_h_ */

/* vi: set ts=4 sw=4 cindent: */
