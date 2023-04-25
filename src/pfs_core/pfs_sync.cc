/*
 * Copyright (c) 2023, Netease Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Author: Xu Yifeng
 */

#include "pfs_tls.h"

#include <stdint.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <sys/time.h>
#include <unistd.h>

#include "pfs_errno_wrapper.h"

static inline int
futex(uint32_t *uaddr, int futex_op, uint32_t val,
      const struct timespec *timeout, uint32_t *uaddr2, uint32_t val3)
{
    return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3);
}

#if PFS_USE_BTHREAD
#include <bthread/butex.h>
#else
#include <atomic>
#endif

struct pfs_tid {
};

pfs_thread_id_t pfs_current_id(void)
{
	pfs_tls_t *tls = pfs_current_tls();
	return (struct pfs_tid *)(uintptr_t)tls;
}

#if PFS_USE_BTHREAD
using namespace bthread;
void pfs_event_init(pfs_event_t *e)
{
	e->butex = butex_create();
	butil::atomic<int> *value = (butil::atomic<int> *)e->butex;
	value->store(0, butil::memory_order_relaxed);
}

void pfs_event_destroy(pfs_event_t *e)
{
	butex_destroy(e->butex);
}

void pfs_event_wait(pfs_event_t *e)
{
	butex_wait(e->butex, 0, NULL);
	butil::atomic<int> *value = (butil::atomic<int> *)e->butex;
	value->store(0);
}

int pfs_event_timedwait(pfs_event_t *e, const struct timespec *abstime) {
    pfs_event_wait(e);
    // TODO(xuchaojie):   implement bthead version pfs_event_timedwait
    return 0;
}

void pfs_event_set(pfs_event_t *e)
{
	butil::atomic<int> *value = (butil::atomic<int> *)e->butex;
	butil::atomic_thread_fence(butil::memory_order_seq_cst);
	if (value->load())
		return;
	value->store(1, butil::memory_order_release);
	butex_wake(e->butex);
}

#else

void pfs_event_init(pfs_event_t *e)
{
	pfs_futex_event_init(&e->value);
}

void pfs_event_destroy(pfs_event_t *e)
{
	pfs_futex_event_destroy(&e->value);
}

void pfs_event_wait(pfs_event_t *e)
{
	pfs_futex_event_wait(&e->value);
}

int pfs_event_timedwait(pfs_event_t *e, const struct timespec *abstime) {
    return pfs_futex_event_timedwait(&e->value, abstime);
}

void pfs_event_set(pfs_event_t *e)
{
	pfs_futex_event_set(&e->value);
}

#endif
