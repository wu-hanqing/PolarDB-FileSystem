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

#ifndef PFS_LOCKTABLE_H
#define PFS_LOCKTABLE_H

#include <stdint.h>

struct rangelock;
typedef struct locktable locktable_t;

struct locktable *pfs_locktable_init();
void  		  pfs_locktable_destroy(locktable_t *t);
struct rangelock *pfs_locktable_get_rangelock(locktable_t *t, uint64_t blkno);
void              pfs_locktable_put_rangelock(locktable_t *t, uint64_t blkno,
			struct rangelock *rl);
#endif
