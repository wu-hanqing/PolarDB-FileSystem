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
 */

#include "pfs_rangelock.h"
#include "pfs_memory.h"
#include "pfs_trace.h"
#include "pfs_impl.h"
#include "pfs_tls.h"

#include "pfs_errno_wrapper.h"

#if PFS_USE_BTHREAD
#define MAX_RQLE_CACHE 128
#else
#define MAX_RQLE_CACHE 3
#endif

struct rl_q_entry {
	union {
		TAILQ_ENTRY(rl_q_entry) rl_q_link;
		struct rl_q_entry *rl_next;
	};
	off_t		rl_q_start, rl_q_end;
	int		rl_q_flags;
	pfs_cond_t	rl_q_cond;
};

static struct rl_q_entry *
rlqentry_alloc(void)
{
	pfs_g_tls_t *current = pfs_current_g_tls();
	struct rl_q_entry *rlqe;

	if ((rlqe = current->tls_rlqe)) {
		current->tls_rlqe = rlqe->rl_next;
		current->tls_rlqe_count--;
		return rlqe;
	}
	rlqe = (struct rl_q_entry *)
		pfs_mem_malloc(sizeof(struct rl_q_entry), M_RANGE_LOCK);
	if (rlqe) {
		memset(rlqe, 0, sizeof(*rlqe));
		pfs_cond_init(&rlqe->rl_q_cond);
	}
	return rlqe;
}

static void
rlqentry_free(struct rl_q_entry *rlqe)
{
	pfs_cond_destroy(&rlqe->rl_q_cond);
	pfs_mem_free(rlqe, M_RANGE_LOCK);
}

static void
rlqentry_release(struct rl_q_entry *rlqe)
{
	pfs_g_tls_t *current = pfs_current_g_tls();
	if (current->tls_rlqe_count >= MAX_RQLE_CACHE) {
		rlqentry_free(rlqe);
	} else {
		rlqe->rl_next = current->tls_rlqe;
		current->tls_rlqe = rlqe;
		current->tls_rlqe_count++;
	}
}

void
pfs_rangelock_thread_exit(void)
{
	pfs_g_tls_t *current = pfs_current_g_tls();
	struct rl_q_entry *rlqe;

	while ((rlqe = current->tls_rlqe)) {
		current->tls_rlqe = rlqe->rl_next;
		current->tls_rlqe_count--;
		rlqentry_free(rlqe);
	}
}

void
pfs_rangelock_init(struct rangelock *lock)
{
	TAILQ_INIT(&lock->rl_waiters);
	lock->rl_currdep = NULL;
	pfs_mutex_init(&lock->rl_mutex); // FIXME adaptive spin for pthread
}

void
pfs_rangelock_destroy(struct rangelock *lock)
{

	PFS_ASSERT(TAILQ_EMPTY(&lock->rl_waiters));
	pfs_mutex_destroy(&lock->rl_mutex);
}

/*
 * Two entries are compatible if their ranges do not overlap, or both
 * entries are for read.
 */
static int
ranges_overlap(const struct rl_q_entry *e1,
    const struct rl_q_entry *e2)
{

	if (e1->rl_q_start < e2->rl_q_end && e1->rl_q_end > e2->rl_q_start)
		return (1);
	return (0);
}

/*
 * Recalculate the lock->rl_currdep after an unlock.
 */
static void
rangelock_calc_block(struct rangelock *lock)
{
	struct rl_q_entry *entry, *nextentry, *entry1;

	for (entry = lock->rl_currdep; entry != NULL; entry = nextentry) {
		nextentry = TAILQ_NEXT(entry, rl_q_link);
		if (entry->rl_q_flags & RL_LOCK_READ) {
			/* Reads must not overlap with granted writes. */
			for (entry1 = TAILQ_FIRST(&lock->rl_waiters);
			    !(entry1->rl_q_flags & RL_LOCK_READ);
			    entry1 = TAILQ_NEXT(entry1, rl_q_link)) {
				if (ranges_overlap(entry, entry1))
					goto out;
			}
		} else {
			/* Write must not overlap with any granted locks. */
			for (entry1 = TAILQ_FIRST(&lock->rl_waiters);
			    entry1 != entry;
			    entry1 = TAILQ_NEXT(entry1, rl_q_link)) {
				if (ranges_overlap(entry, entry1))
					goto out;
			}

			/* Move grantable write locks to the front. */
			TAILQ_REMOVE(&lock->rl_waiters, entry, rl_q_link);
			TAILQ_INSERT_HEAD(&lock->rl_waiters, entry, rl_q_link);
		}

		/* Grant this lock. */
		entry->rl_q_flags |= RL_LOCK_GRANTED;
		pfs_cond_signal(&entry->rl_q_cond);
	}
out:
	lock->rl_currdep = entry;
}

static void
rangelock_unlock_locked(struct rangelock *lock, struct rl_q_entry *entry,
    pfs_mutex_t *ilk, bool do_calc_block)
{
	pfs_tls_t *current = pfs_current_tls();

	PFS_ASSERT(lock != NULL && entry != NULL && ilk != NULL);

	if (!do_calc_block) {
		/*
		 * This is the case where rangelock_enqueue() has been called
		 * with trylock == true and just inserted this entry in the
		 * queue.
		 * If rl_currdep is this entry, rl_currdep needs to
		 * be set to the next entry in the rl_waiters list.
		 * However, since this entry is the last entry in the
		 * list, the next entry is NULL.
		 */
		if (lock->rl_currdep == entry) {
			PFS_ASSERT(TAILQ_NEXT(lock->rl_currdep, rl_q_link) == NULL);
			lock->rl_currdep = NULL;
		}
	} else
		PFS_ASSERT(entry != lock->rl_currdep);

	TAILQ_REMOVE(&lock->rl_waiters, entry, rl_q_link);
	if (do_calc_block)
		rangelock_calc_block(lock);
	rlqentry_release(entry);
}

void
pfs_rangelock_unlock(struct rangelock *lock, void *cookie, pfs_mutex_t *ilk)
{

	PFS_ASSERT(lock != NULL && cookie != NULL && ilk != NULL);

	rangelock_unlock_locked(lock, (struct rl_q_entry *)cookie, ilk, true);
}

/*
 * Unlock the sub-range of granted lock.
 */
void *
pfs_rangelock_unlock_range(struct rangelock *lock, void *cookie, off_t start,
    off_t end, pfs_mutex_t *ilk)
{
	struct rl_q_entry *entry;

	PFS_ASSERT(lock != NULL && cookie != NULL && ilk != NULL);
	entry = (struct rl_q_entry *) cookie;
	PFS_ASSERT(entry->rl_q_flags & RL_LOCK_GRANTED);
	PFS_ASSERT(entry->rl_q_start == start);
	PFS_ASSERT(entry->rl_q_end >= end);

	if (entry->rl_q_end == end) {
		rangelock_unlock_locked(lock, (struct rl_q_entry *)cookie, ilk, true);
		return (NULL);
	}
	entry->rl_q_end = end;
	rangelock_calc_block(lock);
	return (cookie);
}

/*
 * Add the lock request to the queue of the pending requests for
 * rangelock.  Sleep until the request can be granted unless trylock == true.
 */
static void *
rangelock_enqueue(struct rangelock *lock, off_t start, off_t end, int mode,
    pfs_mutex_t *ilk, bool trylock)
{
	struct rl_q_entry *entry;

	PFS_ASSERT(lock != NULL && ilk != NULL);

	entry = rlqentry_alloc();
	PFS_ASSERT(entry != NULL);
	entry->rl_q_flags = mode;
	entry->rl_q_start = start;
	entry->rl_q_end = end;

	/*
	 * XXXKIB TODO. Check that a thread does not try to enqueue a
	 * lock that is incompatible with another request from the same
	 * thread.
	 */

	TAILQ_INSERT_TAIL(&lock->rl_waiters, entry, rl_q_link);
	/*
	 * If rl_currdep == NULL, there is no entry waiting for a conflicting
	 * range to be resolved, so set rl_currdep to this entry.  If there is
	 * no conflicting entry for this entry, rl_currdep will be set back to
	 * NULL by rangelock_calc_block().
	 */
	if (lock->rl_currdep == NULL)
		lock->rl_currdep = entry;
	rangelock_calc_block(lock);
	while (!(entry->rl_q_flags & RL_LOCK_GRANTED)) {
		if (trylock) {
			/*
			 * For this case, the range is not actually locked
			 * yet, but removal from the list requires the same
			 * steps, except for not doing a rangelock_calc_block()
			 * call, since rangelock_calc_block() was called above.
			 */
			rangelock_unlock_locked(lock, entry, ilk, false);
			return (NULL);
		}
		pfs_cond_wait(&entry->rl_q_cond, ilk);
	}
	return (entry);
}

void *
pfs_rangelock_rlock(struct rangelock *lock, off_t start, off_t end, pfs_mutex_t *ilk)
{

	return (rangelock_enqueue(lock, start, end, RL_LOCK_READ, ilk, false));
}

void *
pfs_rangelock_tryrlock(struct rangelock *lock, off_t start, off_t end,
    pfs_mutex_t *ilk)
{

	return (rangelock_enqueue(lock, start, end, RL_LOCK_READ, ilk, true));
}

void *
pfs_rangelock_wlock(struct rangelock *lock, off_t start, off_t end, pfs_mutex_t *ilk)
{

	return (rangelock_enqueue(lock, start, end, RL_LOCK_WRITE, ilk, false));
}

void *
pfs_rangelock_trywlock(struct rangelock *lock, off_t start, off_t end,
    pfs_mutex_t *ilk)
{
	return (rangelock_enqueue(lock, start, end, RL_LOCK_WRITE, ilk, true));
}

#ifdef INVARIANT_SUPPORT
void
_pf_rangelock_cookie_assert(void *cookie, int what, const char *file, int line)
{
	struct rl_q_entry *entry;
	int flags;

	PFS_ASSERT(cookie != NULL);
	entry = cookie;
	flags = entry->rl_q_flags;
	switch (what) {
	case RCA_LOCKED:
		if ((flags & RL_LOCK_GRANTED) == 0)
			pfs_fatal("rangelock not held @ %s:%d\n", file, line);
		break;
	case RCA_RLOCKED:
		if ((flags & (RL_LOCK_GRANTED | RL_LOCK_READ)) !=
		    (RL_LOCK_GRANTED | RL_LOCK_READ))
			pfs_fatal("rangelock not rlocked @ %s:%d\n", file, line);
		break;
	case RCA_WLOCKED:
		if ((flags & (RL_LOCK_GRANTED | RL_LOCK_WRITE)) !=
		    (RL_LOCK_GRANTED | RL_LOCK_WRITE))
			pfs_fatal("rangelock not wlocked @ %s:%d\n", file, line);
		break;
	default:
		pfs_fatal("Unknown rangelock assertion: %d @ %s:%d", what, file,
		    line);
	}
}
#endif	/* INVARIANT_SUPPORT */
