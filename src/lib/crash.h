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

/**
 * @ingroup lib
 * @file
 *
 * A simple crash handler.
 *
 * @author Christian Biere
 * @date 2006
 */

#ifndef _crash_h_
#define _crash_h_

#include "common.h"

/**
 * This macro is to be used in signal handlers, or wherever it is important
 * to be signal-safe, to record strings to be printed in an I/O vector,
 * which is then to be flushed via writev(), which is an atomic syscall.
 *
 * When using this macro, the following local variable are expected to
 * be visible on the stack:
 *
 *    iovec_t iov[16];
 *    unsigned iov_cnt = 0;
 *
 * The size of the I/O vector may be anything, 16 above is just an example.
 *
 * @attention
 * There is no formatting done here, this is not a printf()-like function.
 * It only records an array of constant strings in a vector.
 */
#define print_str(x) \
G_STMT_START { \
	if (iov_cnt < G_N_ELEMENTS(iov)) { \
		const char *ptr = (x); \
		if (ptr) { \
			iovec_set_base(&iov[iov_cnt], (char *) ptr); \
			iovec_set_len(&iov[iov_cnt], strlen(ptr)); \
			iov_cnt++; \
		} \
	} \
} G_STMT_END

/**
 * Print unsigned quantity into supplied buffer and returns the address
 * within that buffer where the printed string starts (value is generated
 * backwards from the end of the buffer).
 *
 * This routine can be used safely in signal handlers.
 */
static inline WARN_UNUSED_RESULT const char *
print_number(char *dst, size_t size, unsigned long value)
{
	char *p = &dst[size];

	if (size > 0) {
		*--p = '\0';
	}
	while (p != dst) {
		*--p = (value % 10) + '0';
		value /= 10;
		if (0 == value)
			break;
	}
	return p;
}

/*
 * Public interface.
 */

#define CRASH_F_PAUSE	(1 << 0)
#define CRASH_F_GDB		(1 << 1)

void crash_init(const char *pathname, const char *argv0, int flags);
void crash_time(char *buf, size_t buflen);
const char *crash_signame(int signo);
void crash_handler(int signo);

#endif	/* _crash_h_ */
/* vi: set ts=4 sw=4 cindent: */
