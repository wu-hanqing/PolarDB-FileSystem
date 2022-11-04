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

#ifndef PFS_FUTEX_EVENT_H
#define PFS_FUTEX_EVENT_H

typedef struct pfs_futex_event {
    unsigned int value;
} pfs_futex_event_t;

void pfs_futex_event_init(pfs_futex_event_t *e);
void pfs_futex_event_destroy(pfs_futex_event_t *e);
void pfs_futex_event_wait(pfs_futex_event_t *e);
int  pfs_futex_event_timedwait(pfs_futex_event_t *e, const struct timespec *abstime);
void pfs_futex_event_set(pfs_futex_event_t *e);

#endif
