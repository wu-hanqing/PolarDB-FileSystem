/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2009 Konstantin Belousov <kib@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef	_PFS_RANGELOCK_H
#define	_PFS_RANGELOCK_H

#include <sys/queue.h>
#include <sys/types.h>
#include "pfs_sync.h"

#define	RL_LOCK_READ		0x0001
#define	RL_LOCK_WRITE		0x0002
#define	RL_LOCK_TYPE_MASK	0x0003
#define	RL_LOCK_GRANTED		0x0004

struct rl_q_entry;

/*
 * The structure representing the range lock.  Caller may request
 * read or write access to the range of bytes. Access is granted if
 * all existing lock owners are compatible with the request. Two lock
 * owners are compatible if their ranges do not overlap, or both
 * owners are for read.
 *
 * Access to the structure itself is synchronized with the externally
 * supplied mutex.
 *
 * rl_waiters is the queue containing in order (a) granted write lock
 * requests, (b) granted read lock requests, and (c) in order of arrival,
 * lock requests which cannot be granted yet.
 *
 * rl_currdep is the first lock request that cannot be granted now due
 * to the preceding requests conflicting with it (i.e., it points to
 * position (c) in the list above).
 */
struct rangelock {
	TAILQ_HEAD(, rl_q_entry) rl_waiters;
	struct rl_q_entry	*rl_currdep;
	pfs_mutex_t 	rl_mutex;
};

void	 pfs_rangelock_init(struct rangelock *lock);
void	 pfs_rangelock_destroy(struct rangelock *lock);
void	 pfs_rangelock_unlock(struct rangelock *lock, void *cookie,
	    pfs_mutex_t *ilk);
void	*pfs_rangelock_unlock_range(struct rangelock *lock, void *cookie,
	    off_t start, off_t end, pfs_mutex_t *ilk);
void	*pfs_rangelock_rlock(struct rangelock *lock, off_t start, off_t end,
	    pfs_mutex_t *ilk);
void	*pfs_rangelock_tryrlock(struct rangelock *lock, off_t start, off_t end,
	    pfs_mutex_t *ilk);
void	*pfs_rangelock_wlock(struct rangelock *lock, off_t start, off_t end,
	    pfs_mutex_t *ilk);
void	*pfs_rangelock_trywlock(struct rangelock *lock, off_t start, off_t end,
	    pfs_mutex_t *ilk);
void	 pfs_rlqentry_free(struct rl_q_entry *rlqe);
void	pfs_rangelock_thread_exit();

#if defined(INVARIANTS) || defined(INVARIANT_SUPPORT)
void	_pfs_rangelock_cookie_assert(void *cookie, int what, const char *file,
    int line);
#endif

#ifdef INVARIANTS
#define	pfs_rangelock_cookie_assert_(cookie, what, file, line)	\
	_pfs_rangelock_cookie_assert((cookie), (what), (file), (line))
#else
#define	pfs_rangelock_cookie_assert_(cookie, what, file, line)		(void)0
#endif

#define	pfs_rangelock_cookie_assert(cookie, what)	\
	pfs_rangelock_cookie_assert_((cookie), (what), __FILE__, __LINE__)

/*
 * Assertion flags.
 */
#if defined(INVARIANTS) || defined(INVARIANT_SUPPORT)
#define	RCA_LOCKED	0x0001
#define	RCA_RLOCKED	0x0002
#define	RCA_WLOCKED	0x0004
#endif

#endif	/* _PFS_RANGELOCK_H */
