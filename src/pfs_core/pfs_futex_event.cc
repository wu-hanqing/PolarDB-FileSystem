/*
 *  Copyright (c) 2022 NetEase Inc.
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

/*
 * Project: curve
 * File Created: 2022-11-4
 * Author: XuYifeng
 */

#include "pfs_futex_event.h"
#include "pfs_util.h"

#include <linux/futex.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <sys/time.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>

static inline int
futex(uint32_t *uaddr, int futex_op, uint32_t val,
      const struct timespec *timeout, uint32_t *uaddr2, uint32_t val3)
{
	return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3);
}

#define EVF_WAIT 0x01
#define EVF_SIG  0x02

void pfs_futex_event_init(pfs_futex_event_t *e)
{
	e->value = 0;
}

void pfs_futex_event_destroy(pfs_futex_event_t *e)
{
}

void pfs_futex_event_wait(pfs_futex_event_t *e)
{
	int v;

	v = __atomic_load_n(&e->value, __ATOMIC_RELAXED);
	for (;;) {
		if (v & EVF_SIG) {
			// event signaled, clear and return
			__atomic_exchange_n(&e->value, 0, __ATOMIC_ACQUIRE);
			return;
		}
		// set waiter flag
		if (!__atomic_compare_exchange_n(&e->value, &v, v | EVF_WAIT,
			 false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
			continue;
		}
		// have set waiter flag, so we can wait
		futex(&e->value, FUTEX_WAIT, v | EVF_WAIT, NULL, NULL, 0);
	}
}

int pfs_futex_event_timedwait(pfs_futex_event_t *e,
	const struct timespec *abstime)
{
	int ret = 0, v;

	v = __atomic_load_n(&e->value, __ATOMIC_RELAXED);
	for (;;) {
		if (v & EVF_SIG) {
			// event signaled, clear and return
			__atomic_exchange_n(&e->value, 0, __ATOMIC_ACQUIRE);
			ret = 0;
			break;
		}
		// set waiter flag
		if (!__atomic_compare_exchange_n(&e->value, &v, v | EVF_WAIT,
			 false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
			continue;
		}
		struct timespec delta, *tsp = NULL;
		if (abstime) {
			tsp = &delta;
			struct timespec now;
			clock_gettime(CLOCK_REALTIME, &now);
			if (pfs_timespeccmp(&now, abstime, >=)) {
				ret = ETIMEDOUT;
				break;
			}
			pfs_timespecsub(&now, abstime, &delta);
		}
		// have set waiter flag, so we can wait
		futex(&e->value, FUTEX_WAIT, v | EVF_WAIT, tsp, NULL, 0);
	}

	return ret;
}

void pfs_futex_event_set(pfs_futex_event_t *e)
{
	int v;

	v = __atomic_load_n(&e->value, __ATOMIC_RELAXED);
	do {
		if (v & EVF_SIG) {
			// already signaled
			return;
		}
		// set signal flag
	} while (!__atomic_compare_exchange_n(&e->value, &v, v | EVF_SIG, false,
				__ATOMIC_RELEASE, __ATOMIC_RELAXED));

	if (v & EVF_WAIT) {
		futex(&e->value, FUTEX_WAKE, 1, NULL, NULL, 0);
	}
}

