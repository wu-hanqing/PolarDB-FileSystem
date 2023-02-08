/*
 *  Copyright (c) 2020 NetEase Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */


/**
 * Project : curve
 * Date : 2022/06/07
 * Author: XuYifeng
 */

#include "pfs_locktable.h"
#include "pfs_rangelock.h"
#include "pfs_util.h"
#include "pfs_impl.h"
#include "pfs_tls.h"

#include <rte_stack.h>
#include <rte_malloc.h>

#include "pfs_errno_wrapper.h"

#define LOCKTABLE_BITS 10
#define LOCKTABLE_SIZE (1 << LOCKTABLE_BITS)

#define LOCKTABLE_ITEM_CACHE 1024
#define LOCKTABLE_ITEM_WARM  128

struct locktable_item {
	struct rangelock li_rl;
	union {
		LIST_ENTRY(locktable_item) li_link;
		struct locktable_item *li_next;
    	};
	uint64_t li_blkno;
	int li_refcount;
};

LIST_HEAD(locktable_list, locktable_item);

struct locktable_chain {
	pthread_mutex_t lc_lock;
	struct locktable_list lc_list;
} __attribute__((aligned(PFS_CACHELINE_SIZE)));
 
struct locktable {
	struct locktable_chain lt_chains[LOCKTABLE_SIZE];
};

static struct rte_stack *g_lt_cache;
static pthread_once_t once_control = PTHREAD_ONCE_INIT;

static inline struct locktable_item *
item_alloc_from_local(void)
{
	pfs_g_tls_t *tls = pfs_current_g_tls();
	struct locktable_item *li;

	if ((li = tls->tls_locktable_items) == NULL)
		return NULL;

	tls->tls_locktable_items = li->li_next;
	tls->tls_locktable_item_count--;
	return li;
}

static inline bool
item_free_to_local(struct locktable_item *li)
{
	pfs_g_tls_t *tls = pfs_current_g_tls();
	if (tls->tls_locktable_item_count == 128)
		return false;

	li->li_next = tls->tls_locktable_items;
	tls->tls_locktable_items = li;
	tls->tls_locktable_item_count++;
	return true;
}

static inline struct locktable_item *
item_alloc(void)
{
	struct locktable_item *li;

	if ((li = item_alloc_from_local()) == NULL &&
	    !rte_stack_pop(g_lt_cache, (void **)&li, 1)) {
		if (pfs_mem_memalign((void **)&li, PFS_CACHELINE_SIZE,
			sizeof(*li), M_LOCKITEM)) {
			return NULL;
		}
		pfs_rangelock_init(&li->li_rl);
	}
	li->li_blkno = 0;
	li->li_refcount = 0;
	return li;
}

static inline void
item_free(struct locktable_item *li)
{
	pfs_rangelock_destroy(&li->li_rl);
	pfs_mem_free(li, M_LOCKITEM);
}

static inline void
item_release(struct locktable_item *li)
{
	pfs_tls_t *tls = pfs_current_tls();
	void * const a[] = { li };

	PFS_ASSERT(li->li_refcount == 0);
	PFS_ASSERT(TAILQ_EMPTY(&li->li_rl.rl_waiters));

	if (item_free_to_local(li))
		return;
	if (rte_stack_push(g_lt_cache, a, 1))
		return;
	item_free(li);
}

static void
item_cache_init(void)
{
	char name[128];

	snprintf(name, sizeof(name), "pfs_lt_%d", getpid());
	g_lt_cache = rte_stack_create(name, LOCKTABLE_ITEM_CACHE,
		SOCKET_ID_ANY, RTE_STACK_F_LF);
	if (g_lt_cache == NULL) {
		pfs_fatal("can not allocate locktable cache");
	}
	for (int i = 0; i < LOCKTABLE_ITEM_WARM; ++i) {
		struct locktable_item *li = item_alloc();
		if (li)
			item_release(li);
		else
			break;
	}
}

static inline void
chain_init(struct locktable_chain *ch)
{
	pthread_mutexattr_t attr;

	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ADAPTIVE_NP);
	pthread_mutex_init(&ch->lc_lock, &attr);
	pthread_mutexattr_destroy(&attr);
	LIST_INIT(&ch->lc_list);
}

static inline void
chain_destroy(struct locktable_chain *ch)
{
	PFS_ASSERT(LIST_EMPTY(&ch->lc_list));
	pthread_mutex_destroy(&ch->lc_lock);
}

struct locktable *
pfs_locktable_init(void)
{
	struct locktable *lt;
	struct locktable_item *li;
	int i;

	pthread_once(&once_control, item_cache_init);

	if (pfs_mem_memalign((void **)&lt, PFS_CACHELINE_SIZE, sizeof(*lt),
		M_LOCKTABLE)) {
		return NULL;
	}
	for (i = 0; i < LOCKTABLE_SIZE; ++i) {
		chain_init(&lt->lt_chains[i]);
	}
	
	return lt;
}

void
pfs_locktable_destroy(struct locktable *lt)
{
	struct locktable_item *li;

	for (int i = 0; i < LOCKTABLE_SIZE; ++i) {
		chain_destroy(&lt->lt_chains[i]);
	}

	pfs_mem_free(lt, M_LOCKITEM);
}

struct rangelock *
pfs_locktable_get_rangelock(struct locktable *lt, uint64_t blkno)
{
	struct locktable_item *li = NULL;
	const int idx = hash_64(blkno, LOCKTABLE_BITS);
	struct locktable_chain *lc = &lt->lt_chains[idx];

	pthread_mutex_lock(&lc->lc_lock);
	LIST_FOREACH(li, &lc->lc_list, li_link) {
		if (li->li_blkno == blkno) {
			li->li_refcount++;
			pthread_mutex_unlock(&lc->lc_lock);
			return &li->li_rl;
		}
	}
	li = item_alloc();
	li->li_blkno = blkno;
	LIST_INSERT_HEAD(&lc->lc_list, li, li_link);
	li->li_refcount = 1;
	pthread_mutex_unlock(&lc->lc_lock);
	return &li->li_rl;
}

void
pfs_locktable_put_rangelock(struct locktable *lt, uint64_t blkno,
	struct rangelock *rl)
{
	struct locktable_item *li = container_of(rl, struct locktable_item, li_rl);
	const int idx = hash_64(blkno, LOCKTABLE_BITS);
	struct locktable_chain *lc = &lt->lt_chains[idx];

	PFS_ASSERT(blkno == li->li_blkno);
	pthread_mutex_lock(&lc->lc_lock);
	if (--li->li_refcount == 0) {
		LIST_REMOVE(li, li_link);
	} else {
		li = NULL;
	}
	pthread_mutex_unlock(&lc->lc_lock);
	if (li) {
		item_release(li);
	}
}

void
pfs_locktable_thread_exit(void)
{
	pfs_g_tls_t *tls = pfs_current_g_tls();
	struct locktable_item *p, *next;

	p = tls->tls_locktable_items;
	while (p) {
		next = p->li_next;
		item_free(p);
		p = next;
	}
	tls->tls_locktable_items = NULL;
	tls->tls_locktable_item_count = 0;
}
