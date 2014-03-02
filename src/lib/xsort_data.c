/*
 * Copyright (c) 2014 Raphael Manfredi
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
 * Sorting routines that do not call zalloc() or xmalloc() but whose sorting
 * callback takes an additional parameter.
 *
 * @author Raphael Manfredi
 * @date 2014
 */

#include "common.h"

#include "xsort_data.h"
#include "getphysmemsize.h"
#include "mempcpy.h"
#include "op.h"
#include "unsigned.h"
#include "vmm.h"

#include "override.h"			/* Must be the last header included */

/*
 * Configure xsort-gen.c for extended sorting (cmp_data_fn_t sorting callback).
 */

#define UDATA			, udata
#define UDATA_DECL		, void *udata
#define CMP_FN_T		cmp_data_fn_t
#define XSORT			xsort_with_data
#define XQSORT			xqsort_with_data
#define TAG				_with_data

#include "xsort-gen.c"

/* vi: set ts=4 sw=4 cindent: */
