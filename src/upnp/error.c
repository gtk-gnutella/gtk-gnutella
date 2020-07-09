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
 * @ingroup upnp
 * @file
 *
 * UPnP known error codes.
 *
 * @author Raphael Manfredi
 * @date 2011
 */

#include "common.h"

#include "error.h"

#include "lib/override.h"		/* Must be the last header included */

/**
 * Translates an UPnP error code into a human-readable string.
 */
const char *
upnp_strerror(int code)
{
	switch (code) {
	/*
	 * Locally defined.
	 */
	case 0:		return "OK";
	case 1:		return "Unparseable UPnP SOAP fault";
	case 2:		return "SOAP error";
	case 3:		return "Returned values were un-parseable";
	/*
	 * Defined in the UPnP 1.0 architecture.
	 */
	case 401:	return "Invalid action";
	case 402:	return "Invalid args";
	case 403:	return "Out of sync";		/* Deprecated */
	case 501:	return "Action failed";
	case 600:	return "Argument value invalid";
	case 601:	return "Argument value out of range";
	case 602:	return "Optional action not implemented";
	case 603:	return "Out of memory";
	case 604:	return "Human intervention required";
	case 605:	return "String argument too long";
	case 606:	return "Action not authorized";
	case 607:	return "Signature failure";
	case 608:	return "Signature missing";
	case 609:	return "Not encrypted";
	case 610:	return "Invalid sequence";
	case 611:	return "Invalid control URL";
	case 612:	return "No such session";
	/*
	 * Defined in the WANIPConnection:2 service specifications.
	 */
	case 703:	return "Inactive connection state required";
	case 704:	return "Connection setup failed";
	case 705:	return "Connection setup in progress";
	case 706:	return "Connection not configured";
	case 707:	return "Disconnect in progress";
	case 708:	return "Invalid layer 2 address";
	case 709:	return "Internet access disabled";
	case 710:	return "Invalid connection type";
	case 711:	return "Connection already terminated";
	case 713:	return "Specified array index invalid";
	case 714:	return "No such entry in array";
	case 715:	return "Wildcard not permitted in source IP";
	case 716:	return "Wildcard not permitted in external port";
	case 718:	return "Conflict in mapping entry";
	case 724:	return "Same port values required";
	case 725:	return "Only permanent leases supported";
	case 726:	return "Remote host only supports wildcard";
	case 727:	return "External port only supports wildcard";
	case 728:	return "No port maps available";
	case 729:	return "Conflict with other mechanism";
	case 730:	return "Port mapping not found";
	case 731:	return "Read only value";
	case 732:	return "Wildcard not permitted in internal port";
	case 733:	return "Inconsistent parameter";
	}

	return "Unknown error code";
}


/* vi: set ts=4 sw=4 cindent: */
