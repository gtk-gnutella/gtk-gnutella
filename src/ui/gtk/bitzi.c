/* -*- mode: cc-mode; tab-width:4; -*-
 *
 * $Id$
 *
 * Copyright (c) 2004, Alex Bennee <alex@bennee.com>
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
 * @file
 *
 * Bitzi GTK interface code
 */

#include "gtk/gui.h"

RCSID("$Id$");

#include "gtk/search.h"			/* search_t */
#include "gtk/misc.h"			/* gui_record_sha1_eq() */
#include "gtk/gtk-missing.h"

#include "if/bridge/ui2c.h"
#include "if/core/bitzi.h"    	/* bitzi_data_t */
#include "lib/override.h"		/* Must be the last header included */

/*
 * This table should match the encoding one in core/bitzi.c
 *
 * It assumes the enum's are in order
 */

static const gchar * const bitzi_fj_table[] =
{
	N_("Unknown"),				/* UNKNOWN */
	N_("Dangerous/Misleading"),	/* DANGEROUS_MISLEADING */
	N_("Incomplete/Damaged"),	/* INCOMPLETE_DAMAGED */
	N_("Substandard"),			/* SUBSTANDARD */
	N_("Overrated"),			/* OVERRATED */
	N_("Normal"),				/* NORMAL */
	N_("Underrated"),			/* UNDERRATED */
	N_("Complete"),				/* COMPLETE */
	N_("Recommended"),			/* RECOMMENDED */
	N_("Best Version"),			/* BEST_VERSION*/
};

gchar *
bitzi_fjtostring(bitzi_fj_t fj)
{
	g_assert(fj < G_N_ELEMENTS(bitzi_fj_table));
	return	_(bitzi_fj_table[fj]);
}


void
bitzi_gui_update(bitzi_data_t *bitzi_data)
{
    g_message("bitzi_gui_update: data %p, size %d\n"
			  "goodness %f, judgement %d, type %s, details %s",
			bitzi_data,
			bitzi_data->size,
			bitzi_data->goodness,
			bitzi_data->judgement,
			bitzi_data->mime_type,
			bitzi_data->mime_desc);

	/* Update the various GUI elements */
	
	search_gui_metadata_update(bitzi_data);
	
}

/* vi: set ts=4 sw=4 cindent: */
