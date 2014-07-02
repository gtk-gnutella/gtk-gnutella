/*
 * Copyright (c) 2007, Christian Biere
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
/*
 * Copyright (c) 2006 Christian Biere <christianbiere@gmx.de>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the authors nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "common.h"

#include "base16.h"
#include "ascii.h"
#include "misc.h"

#include "override.h" /* Must be the last header included */

/*
 * See RFC 3548 for details about Base 16 encoding:
 *  http://www.faqs.org/rfcs/rfc3548.html
 */

static const char base16_alphabet[] = "0123456789abcdef";

/**
 * Encode in base16 `len' bytes of `data' into the buffer `dst'.
 *
 * @param dst		destination buffer
 * @param size		length of destination
 * @param data		start of data to encode
 * @param len		amount of bytes to encode
 *
 * @return the amount of bytes generated into the destination.
 */
size_t
base16_encode(char *dst, size_t size, const void *data, size_t len)
{
  const unsigned char *p = data;
  char *q = dst;
  size_t i;

  if (size / 2 < len) {
    len = size / 2;
  }

  for (i = 0; i < len; i++) {
    unsigned char c = p[i] & 0xff;
    *q++ = base16_alphabet[(c >> 4) & 0xf];
    *q++ = base16_alphabet[c & 0xf];
  }

  return q - dst;
}

/**
 * Decode a base16 encoding of `len' bytes of `data' into the buffer `dst'.
 *
 * @param dst		destination buffer
 * @param size		length of destination
 * @param data		start of data to decode
 * @param len		amount of encoded data to decode
 *
 * @return the amount of bytes decoded into the destination, -1 on error.
 */
size_t
base16_decode(char *dst, size_t size, const void *data, size_t len)
{
  const unsigned char *p = data;
  char *q = dst;
  size_t i;

  if G_UNLIKELY(0 == hex2int_inline('a'))
	misc_init();	/* Auto-initialization of hex2int_inline() */

  len /= 2;
  len = 2 * (size < len ? size : len);

  i = 0;
  while (i < len) {
    int high, low;

    high = hex2int_inline(p[i++]);
    if (high < 0)
      return (size_t) -1;
    low = hex2int_inline(p[i++]);
    if (low < 0)
      return (size_t) -1;
    *q++ = (high << 4) | low;
  }

  return q - dst;
}

/* vi: set ai et sts=2 sw=2 cindent: */
