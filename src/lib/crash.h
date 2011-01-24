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
 * The following macros are intended for use in signal handlers, or wherever it
 * is important to be signal-safe, to record strings to be printed in an I/O
 * vector, which is then to be flushed via writev(), which is an atomic
 * syscall.
 *
 * The following example demonstrates typical use:
 *
 *	{
 *		DECLARE_STR(10); // Can add up to 10 strings
 *	    unsigned after_header;
 *
 * 		print_str("Some constant text: ");
 *		after_header = getpos_str();
 * 		print_str(some_variable_text);
 * 		print_str("\n");	// Append a newline character
 *		flush_err_str();	// Sent all strings to STDERR_FILENO with writev()
 *
 *		// The collected strings are still valid and flush_str()
 *		// or flush_err_str() can be used multiple times.
 *
 *		rewind_str(after_header); // rewind to offset 1; keep the first string
 *		print_str(some_other_text); 
 *		flush_str(fd);	// Sent all strings to file descriptor fd with writev()
 *	}
 * 
 * @attention
 * There is no formatting done here, this is not a printf()-like function.
 * It only records an array of constant strings in a vector.
 */

#define DECLARE_STR(num_iov) \
	unsigned print_str_iov_cnt_ = 0; \
	iovec_t print_str_iov_[(num_iov)]

#define print_str(text) \
G_STMT_START { \
	const char *print_str_text_ = (text); \
	if ( \
		print_str_text_ && \
		print_str_iov_cnt_ < G_N_ELEMENTS(print_str_iov_) \
	) { \
		iovec_set_base(&print_str_iov_[print_str_iov_cnt_], \
			(char *) print_str_text_); \
		iovec_set_len(&print_str_iov_[print_str_iov_cnt_], \
			strlen(print_str_text_)); \
		print_str_iov_cnt_++; \
	} \
} G_STMT_END

#define flush_str(fd) \
	IGNORE_RESULT(writev((fd), print_str_iov_, print_str_iov_cnt_))

#define flush_err_str() flush_str(STDERR_FILENO)

#define rewind_str(i) \
G_STMT_START { \
	unsigned rewind_str_i_ = (i); \
	if (rewind_str_i_ <= print_str_iov_cnt_) \
		print_str_iov_cnt_ = (i); \
} G_STMT_END

#define getpos_str(i) (print_str_iov_cnt_)

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
void crash_setdir(const char *dir);
void crash_setver(const char *version);
void crash_setbuild(unsigned build);
void crash_post_init(void);

#endif	/* _crash_h_ */
/* vi: set ts=4 sw=4 cindent: */
