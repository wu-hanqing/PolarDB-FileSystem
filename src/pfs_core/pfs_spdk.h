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

#ifndef _PFS_SPDK_3dee546e_H
#define _PFS_SKDK_3dee546e_H

#include <spdk/stdinc.h>
#include <spdk/bdev.h>
#include <spdk/thread.h>
#include <spdk/queue.h>

#include <sched.h>

class pfs_spdk_thread_guard {
    struct spdk_thread *thread_;

    pfs_spdk_thread_guard(const pfs_spdk_thread_guard &);
    void operator= (const pfs_spdk_thread_guard &);

public:
    pfs_spdk_thread_guard() {
        thread_ = spdk_get_thread();
    }
    ~pfs_spdk_thread_guard() {
        if (thread_)
            spdk_set_thread(thread_);
    }
    void release() {
        thread_ = 0;
    }
};

void pfs_spdk_conf_set_blocked_pci(const char *s);
void pfs_spdk_conf_set_allowed_pci(const char *s);
void pfs_spdk_conf_set_json_config_file(const char *s);
void pfs_spdk_conf_set_name(const char *s);
void pfs_spdk_conf_set_env_context(const char *s);
void pfs_spdk_conf_set_controller(const char *s);

void pfs_spdk_gc_thread(struct spdk_thread *thread);
void pfs_spdk_teardown_thread(struct spdk_thread *thread);

int pfs_get_pci_local_cpus(const char *pci_addr, cpu_set_t *setp);
char* pfs_get_dev_pci_address(struct spdk_bdev *dev);
int pfs_get_dev_local_cpus(struct spdk_bdev *bdev, cpu_set_t *setp);
char *pfs_cpuset_to_string(const cpu_set_t *mask);
int pfs_parse_set(const char *input, cpu_set_t *setp);
int pfs_cpuset_socket_id(cpu_set_t *setp);
int pfs_iov_is_prp_aligned(const struct iovec *iov, int iovcnt);
int pfs_is_prp_aligned(const void *addr, size_t len);

#define pfs_iov_is_sge_aligned(iov, iovcnt) \
	pfs_iov_is_prp_aligned(iov, iovcnt)

#define pfs_is_sge_aligned(addr, len) \
	pfs_is_prp_aligned(iov, iovcnt)

#include "pfs_spdk_api.h"

#endif
