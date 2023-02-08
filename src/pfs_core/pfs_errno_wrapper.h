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

#pragma once

/*********************************************************************
The glibc defines errno as following:

extern int *__errno_location (void) __THROW __attribute_const__; 
# define errno (*__errno_location ())

The above code leads compiler to believe that address of errno is
not changed in thread context, but in bthread world, this is not the
case because bthread can migrate between different pthreads, thus
we redefine errno as its address changable.
**********************************************************************/

#if PFS_USE_BTHREAD

#undef errno
#define errno (*__pfs_errno())

#ifdef __cplusplus
extern "C" {
#endif

extern int *__pfs_errno(void);

#ifdef __cplusplus
}
#endif

#endif
