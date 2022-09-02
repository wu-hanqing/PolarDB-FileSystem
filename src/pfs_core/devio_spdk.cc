/* vim: set ts=4 sw=4 expandtab: */
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
 * File Created: 2022-5-7
 * Author: XuYifeng
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <semaphore.h>
#include <gflags/gflags.h>

#include <spdk/env.h>
#include <spdk/log.h>
#include <spdk/string.h>
#include <rte_common.h>
#include <rte_memcpy.h>
#include <rte_thread.h>
#include <rte_pause.h>

#include "pfs_trace.h"
#include "pfs_devio.h"
#include "pfs_memory.h"
#include "pfs_option.h"
#include "pfs_impl.h"
#include "pfs_spdk.h"
#include "pfs_util.h"

#define BUF_TYPE "pfs_iobuf"
#define io_buf io_iov[0].iov_base

#define timespecadd(tsp, usp, vsp)                              \
    do {                                                        \
        (vsp)->tv_sec = (tsp)->tv_sec + (usp)->tv_sec;          \
        (vsp)->tv_nsec = (tsp)->tv_nsec + (usp)->tv_nsec;       \
        if ((vsp)->tv_nsec >= 1000000000L) {                    \
            (vsp)->tv_sec++;                                    \
            (vsp)->tv_nsec -= 1000000000L;                      \
        }                                                       \
    } while (0)

typedef struct pfs_spdk_iocb pfs_spdk_iocb_t;

typedef struct pfs_spdk_dev {
    /* must be first member */
    pfs_dev_t   dk_base;
    struct spdk_bdev_desc *dk_desc;
    struct spdk_bdev      *dk_bdev;
    uint32_t    dk_sectsz;
    uint64_t    dk_size;
    uint64_t    dk_block_num;
    uint32_t    dk_block_size;
    uint32_t    dk_unit_size;
    int         dk_has_cache;
#define dk_bufalign dk_base.d_buf_align
    pthread_t   dk_pthread;
    struct pfs_spdk_thread *dk_thread;
    struct spdk_io_channel *dk_ioch;
    int         dk_stop;
    int         dk_jobs;

    pfs_spdk_iocb_t *dk_incoming __rte_aligned(RTE_CACHE_LINE_SIZE);
    sem_t       dk_sem;
    char        dk_path[128];
} pfs_spdk_dev_t;

struct pfs_spdk_iocb {
    pfs_devio_t             *cb_pfs_io;
    void                    *cb_dma_buf;
    pfs_spdk_dev_t          *cb_dev;
    struct pfs_spdk_ioq     *cb_ioq;
    spdk_msg_fn             cb_io_op;
    spdk_msg_fn             cb_io_done;
    union {
        SLIST_ENTRY(pfs_spdk_iocb) cb_free;
        pfs_spdk_iocb_t *cb_next;
    };
    struct spdk_bdev_io_wait_entry cb_bdev_io_wait;
};

typedef struct pfs_spdk_ioq {
    /* must be first member */
    pfs_ioq_t   dkq_ioq;
#define dkq_destroy     dkq_ioq.ioq_destroy

    int         dkq_inflight_count;
    int         dkq_complete_count;
    TAILQ_HEAD(, pfs_devio) dkq_inflight_queue;
    TAILQ_HEAD(, pfs_devio) dkq_complete_queue;

    pfs_spdk_iocb_t *dkq_done_q __rte_aligned(RTE_CACHE_LINE_SIZE);
    pfs_event_t dkq_done_ev;
    char	dkq_pad[RTE_CACHE_LINE_SIZE];
} pfs_spdk_ioq_t;

struct bdev_open_param {
    pfs_spdk_dev_t *dkdev;
    sem_t sem;
    int rc;
};

static const int64_t g_iodepth = 128;
DEFINE_int32(pfs_spdk_driver_poll_delay, 0,
  "pfs spdk driver busy poll delay time(us)");
DEFINE_bool(pfs_spdk_driver_auto_cpu_bind, false,
  "pfs spdk driver auto bind thread to cpus which are nearest to pci device");
DEFINE_string(pfs_spdk_driver_cpu_bind, "", 
  "pfs spdk driver list [device@dpdk_cpu_set] should bind to cpu set to");
DEFINE_int32(pfs_spdk_driver_error_interval, 1,
  "pfs spdk driver DMA buffer allocation failure report interval (seconds)");
DEFINE_string(pfs_spdk_driver_check_pci_address, "", 
  "pfs spdk device list [device@domain:bus:dev.function;] to check pci address");
DEFINE_bool(pfs_spdk_driver_auto_dma, true,
  "pfs spdk driver always use dma buffer if not allocated");

#define PFS_MAX_CACHED_SPDK_IOCB        128
static __thread SLIST_HEAD(, pfs_spdk_iocb) tls_free_iocb = {NULL};
static __thread int tls_free_iocb_num = 0;

#define error_time_interval {FLAGS_pfs_spdk_driver_error_interval, 0}

static struct timeval err_time_interval={1,0};

static void pfs_spdk_dev_io_fini_pread(void *iocb);
static void pfs_spdk_dev_io_fini_pwrite(void *iocb);
static void pfs_spdk_dev_io_fini_trim(void *iocb);
static void pfs_spdk_dev_io_fini_flush(void *iocb);
static void pfs_spdk_dev_pull_iocb(pfs_spdk_dev_t *dkdev);

static pfs_spdk_iocb_t *
pfs_spdk_dev_alloc_iocb(void)
{
    pfs_spdk_iocb_t *iocb = NULL;
    void *p = NULL;
    int err = -1;

    /* try to get it from local cache */
    iocb = SLIST_FIRST(&tls_free_iocb);
    if (iocb != NULL) {
        SLIST_REMOVE_HEAD(&tls_free_iocb, cb_free);
        tls_free_iocb_num--;
    } else {
        /* allocate it by malloc from global heap */
        err = pfs_mem_memalign(&p, PFS_CACHELINE_SIZE, sizeof(*iocb),
		M_SPDK_IOCB);
        if (err) {
            pfs_etrace("create iocb failed, %s\n", strerror(err));
            abort();
        }
        iocb = (pfs_spdk_iocb_t *)p;
    }
    memset(iocb, 0, sizeof(*iocb));
    return iocb;
}

static void
pfs_spdk_dev_free_iocb(pfs_spdk_iocb_t *iocb)
{
    if (tls_free_iocb_num < PFS_MAX_CACHED_SPDK_IOCB) {
        SLIST_INSERT_HEAD(&tls_free_iocb, iocb, cb_free);
        tls_free_iocb_num++;
    } else {
        pfs_mem_free(iocb, M_SPDK_IOCB);
    }
}

static void
pfs_spdk_dev_destroy_ioq(pfs_ioq_t *ioq)
{
    pfs_spdk_ioq_t *dkioq = (pfs_spdk_ioq_t *)ioq;
    int err;

    PFS_ASSERT(dkioq->dkq_inflight_count == 0);
    PFS_ASSERT(TAILQ_EMPTY(&dkioq->dkq_inflight_queue));

    PFS_ASSERT(dkioq->dkq_complete_count == 0);
    PFS_ASSERT(TAILQ_EMPTY(&dkioq->dkq_complete_queue));

    pfs_event_destroy(&dkioq->dkq_done_ev);
    pfs_mem_free(dkioq, M_SPDK_DEV_IOQ);
}

static pfs_ioq_t *
pfs_spdk_dev_create_ioq(pfs_dev_t *dev)
{
    pfs_spdk_ioq_t *dkioq = NULL;
    void *p = NULL;
    int err;

    err = pfs_mem_memalign(&p, PFS_CACHELINE_SIZE, sizeof(*dkioq),
		M_SPDK_DEV_IOQ);
    if (err) {
        pfs_etrace("create disk ioq failed: %d, %s\n", strerror(err));
        return NULL;
    }
    memset(p, 0, sizeof(*dkioq));
    dkioq = (pfs_spdk_ioq_t *)p;
    dkioq->dkq_destroy = pfs_spdk_dev_destroy_ioq;
    dkioq->dkq_inflight_count = 0;
    dkioq->dkq_complete_count = 0;
    TAILQ_INIT(&dkioq->dkq_inflight_queue);
    TAILQ_INIT(&dkioq->dkq_complete_queue);
    pfs_event_init(&dkioq->dkq_done_ev);
    return (pfs_ioq_t *)dkioq;
}

static bool
pfs_spdk_dev_need_throttle(pfs_dev_t *dev, pfs_ioq_t *ioq)
{
    pfs_spdk_ioq_t *dkioq = (pfs_spdk_ioq_t *)ioq;
    return (dkioq->dkq_inflight_count >= g_iodepth);
}

static void
bdev_event_cb(enum spdk_bdev_event_type type, struct spdk_bdev *bdev,
    void *event_ctx)
{
    pfs_etrace("Unsupported spdk bdev event: type %d\n", type);
    return;
}

static int
bdev_thread_bind_cpuset(const char *thread_name, pfs_spdk_dev_t *dkdev)
{
    pfs_dev_t *dev = &dkdev->dk_base;
    cpu_set_t cpuset;
    int err = 0;

    err = pfs_get_dev_local_cpus(dkdev->dk_bdev, &cpuset);
    if (err == 0) {
        dev->d_mem_socket_id = pfs_cpuset_socket_id(&cpuset);
    } else {
        pfs_etrace("cannot get device %s's local cpuset", dev->d_devname);
    }

    if (FLAGS_pfs_spdk_driver_auto_cpu_bind) {
        if (err == 0) {
set_it:
            std::string cpuset_str = pfs_cpuset_to_string(&cpuset);
            err = rte_thread_set_affinity(&cpuset);
            if (err == 0) {
                pfs_itrace("auto bind thread %s to cpuset : %s", thread_name,
                        cpuset_str.c_str());
            } else {
                pfs_etrace("cannot bind thread %s to cpuset: %s", thread_name,
                        cpuset_str.c_str());
                err = -1;
            }
        }
    } else if (!FLAGS_pfs_spdk_driver_cpu_bind.empty()) {
        std::string &s = FLAGS_pfs_spdk_driver_cpu_bind;
        auto pos = s.find(dev->d_devname);
        if (pos != std::string::npos) {
            pos += strlen(dev->d_devname);
            if (s[pos] != '@') {
                pfs_etrace("cannot find cpuset bind for %s in %s",
                     dev->d_devname, s.c_str());
                err = -1;
            } else {
                pos++;
                auto pos2 = s.find(';', pos);
                std::string substr;
                if (pos2 != std::string::npos)
                    substr = s.substr(pos2-pos);
                else
                    substr = s.substr(pos);

                if (pfs_parse_set(substr.c_str(), &cpuset) == substr.length())
                    goto set_it;
                else {
                    pfs_etrace("can not parse cpuset %s", substr.c_str());
                    err = -1;
                }
            }
        } else {
            pfs_etrace("no cpuset found in cpuset bind %s for %s", s.c_str(),
                       dev->d_devname);
        }
    }

    return err;
}

static int
bdev_check_pci_address(pfs_spdk_dev_t *dkdev)
{
    pfs_dev_t *dev = &dkdev->dk_base;
    std::string pci_address = pfs_get_dev_pci_address(dkdev->dk_bdev);

    if (pci_address.empty()) {
        pfs_wtrace("device %s has empty pci address", dev->d_devname);
        return 0;
    }

    pfs_itrace("device %s, current pci address %s", dev->d_devname,
        pci_address.c_str());

    if (!FLAGS_pfs_spdk_driver_check_pci_address.empty()) {
        std::string &s = FLAGS_pfs_spdk_driver_check_pci_address;
        auto pos = s.find(dev->d_devname);
        if (pos != std::string::npos) {
            pos += strlen(dev->d_devname);
            if (s[pos] != '@') {
                pfs_etrace("cannot find ':' for %s in %s",
                     dev->d_devname, s.c_str());
                return -1;
            } else {
                pos++;
                auto pos2 = s.find(';', pos);
                std::string substr;
                if (pos2 != std::string::npos)
                    substr = s.substr(pos2-pos);
                else
                    substr = s.substr(pos);
                if (substr == pci_address) {
                    pfs_itrace("ok to verify pci address for %s", dev->d_devname);
                    return 0;
                } else {
                    pfs_etrace("pci address is not match for %s, current: %s, expected: %s",
                        dev->d_devname, pci_address.c_str(), substr.c_str());
                    return -1;
                }
            }
        } else {
            pfs_wtrace("device %s is not in pfs_spdk_driver_check_pci_address",
                dev->d_devname);
        }
    }

    return 0;
}

/*
    return param.rc:
	failure: > 0
	success: 0
*/
static void *
bdev_thread_msg_loop(void *arg)
{
    struct bdev_open_param *param = (struct bdev_open_param *)arg;
    pfs_spdk_dev_t *dkdev = param->dkdev;
    pfs_dev_t *dev = &dkdev->dk_base;
    struct pfs_spdk_thread *thread = NULL;
    char thread_name[64];
    int err;

    snprintf(thread_name, sizeof(thread_name), "pfs-dev-%s", dev->d_devname);
    pthread_setname_np(pthread_self(), thread_name);
    thread = pfs_create_spdk_thread(thread_name);
    err = spdk_bdev_open_ext(dev->d_devname, dev_writable(dev),
                             bdev_event_cb, dkdev, &dkdev->dk_desc);
    if (err) {
        pfs_etrace("can not open spdk device %s, %s\n", dev->d_devname,
                   strerror(-err));
err_exit:
        param->rc = -err;
        sem_post(&param->sem);
        return NULL;
    }
    dkdev->dk_bdev = spdk_bdev_desc_get_bdev(dkdev->dk_desc);
    if (bdev_check_pci_address(dkdev) == -1) {
        spdk_bdev_close(dkdev->dk_desc);
        err = EINVAL;
        goto err_exit;
    }

    dkdev->dk_ioch = pfs_get_spdk_io_channel(dkdev->dk_desc);
    if (dkdev->dk_ioch == NULL) {
        pfs_etrace("can not get io channel of spdk device: %s\n",
            dev->d_devname);
        spdk_bdev_close(dkdev->dk_desc);
        err = ENOMEM;
        goto err_exit;
    }
    strncpy(dkdev->dk_path, dev->d_devname, sizeof(dkdev->dk_path));
    dkdev->dk_path[sizeof(dkdev->dk_path)-1] = 0;
    dkdev->dk_block_num = spdk_bdev_get_num_blocks(dkdev->dk_bdev);
    dkdev->dk_block_size = spdk_bdev_get_block_size(dkdev->dk_bdev);
    dkdev->dk_unit_size = spdk_bdev_get_write_unit_size(dkdev->dk_bdev);
    dkdev->dk_thread = thread;
    dkdev->dk_sectsz = dkdev->dk_unit_size * dkdev->dk_block_size;
    dkdev->dk_has_cache = spdk_bdev_has_write_cache(dkdev->dk_bdev);
    dkdev->dk_size = dkdev->dk_block_num * dkdev->dk_block_size;
    dkdev->dk_bufalign = spdk_bdev_get_buf_align(dkdev->dk_bdev);
    if (dkdev->dk_bufalign < 4096)
        dkdev->dk_bufalign = 4096;
    dev->d_cap = DEV_CAP_RD | DEV_CAP_WR | DEV_CAP_FLUSH | DEV_CAP_TRIM;
    if (spdk_bdev_io_type_supported(dkdev->dk_bdev,
			SPDK_BDEV_IO_TYPE_WRITE_ZEROES)) {
	    dev->d_cap |= DEV_CAP_ZERO;
    }
    dev->d_write_unit = spdk_bdev_get_write_unit_size(dkdev->dk_bdev) *
		spdk_bdev_get_block_size(dkdev->dk_bdev);
    PFS_ASSERT(RTE_IS_POWER_OF_2(dev->d_write_unit));

    pfs_itrace("open spdk device: '%s', block_num: %ld, "
               "block_size: %d, write_unit_size: %d, has_cache: %d, buf_align:%d\n",
               dev->d_devname, dkdev->dk_block_num, dkdev->dk_block_size,
               dkdev->dk_unit_size, dkdev->dk_has_cache, dkdev->dk_bufalign);

    bdev_thread_bind_cpuset(thread_name, dkdev);

    param->rc = 0;
    sem_post(&param->sem);

    struct spdk_thread *spdk_thread = thread->spdk_thread;
    struct timespec timeout = {0, FLAGS_pfs_spdk_driver_poll_delay * 1000};
    while (!dkdev->dk_stop) {
        pfs_spdk_dev_pull_iocb(dkdev);
        while (dkdev->dk_jobs != 0) {
            spdk_thread_poll(spdk_thread, 0, spdk_get_ticks());
            pfs_spdk_dev_pull_iocb(dkdev);
        }
        if (FLAGS_pfs_spdk_driver_poll_delay)
            continue;
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        timespecadd(&ts, &timeout, &ts);
        sem_timedwait(&dkdev->dk_sem, &ts);
    }
 
    pfs_put_spdk_io_channel(dkdev->dk_ioch);
    spdk_bdev_close(dkdev->dk_desc);

    while (spdk_thread_poll(spdk_thread, 0, 0))
        {}
    return NULL;
}

/*
 * return:
 *    failure: < 0
 *    sucess : 0
 */
static int
pfs_spdk_dev_open(pfs_dev_t *dev)
{
    pfs_spdk_dev_t *dkdev = (pfs_spdk_dev_t *)dev;
    struct spdk_thread *origin, *thread;
    struct bdev_open_param param;
    int err;

    /*
     * pfs_spdk_setup should be called as soone as possible in
     * application's main thread earlier, put it here is just easy
     * for pfs tools.
     */
    if ((err = pfs_spdk_setup())) {
        pfs_etrace("can not init spdk env");
        return -EIO;
    }
    sem_init(&param.sem, 0, 0);
    param.dkdev = dkdev;
    param.rc = 0;
 
    dkdev->dk_stop = 0;
    dkdev->dk_jobs = 0;
    sem_init(&dkdev->dk_sem, 0, 0);
    err = pthread_create(&dkdev->dk_pthread, NULL, bdev_thread_msg_loop,
                         &param);
    if (err) {
        sem_destroy(&dkdev->dk_sem);
        pfs_etrace("can not create device msg thread %s, %s\n", dev->d_devname,
                   strerror(err));
        return -err;
    }

    sem_wait(&param.sem);
    sem_destroy(&param.sem);
    if (param.rc) {
        pthread_join(dkdev->dk_pthread, NULL);
    }
    return -param.rc;
}

static int
pfs_spdk_dev_close(pfs_dev_t *dev)
{
    pfs_spdk_dev_t *dkdev = (pfs_spdk_dev_t *)dev;

    if (dkdev->dk_desc == NULL)
        return 0;
    
    dkdev->dk_stop = 1;
    sem_post(&dkdev->dk_sem);
    pthread_join(dkdev->dk_pthread, NULL);
    sem_destroy(&dkdev->dk_sem);
    return 0;
}

static int
pfs_spdk_dev_reopen(pfs_dev_t *dev)
{
    pfs_spdk_dev_close(dev);
    return pfs_spdk_dev_open(dev);
}

static int
pfs_spdk_dev_info(pfs_dev_t *dev, struct pbdinfo *pi)
{
    pfs_spdk_dev_t *dkdev = (pfs_spdk_dev_t *)dev;
    size_t size = dkdev->dk_block_num * dkdev->dk_block_size;

    pi->pi_pbdno = 0;
    pi->pi_unitsize = (4UL << 20);
    pi->pi_chunksize = (10ULL << 30);
    pi->pi_disksize = (size / pi->pi_chunksize) * pi->pi_chunksize;
    pi->pi_rwtype = 1; // FIXME

    pfs_itrace("%s get pi_pbdno %u, pi_rwtype %d, pi_unitsize %llu, "
               "pi_chunksize %llu, pi_disksize %llu\n",
               __func__, pi->pi_pbdno, pi->pi_rwtype,
               pi->pi_unitsize, pi->pi_chunksize, pi->pi_disksize);
    pfs_itrace("%s waste size: %llu\n", __func__, size - pi->pi_disksize);
    return 0;
}

static int
pfs_spdk_dev_reload(pfs_dev_t *dev)
{
    return 0;
}

static inline bool
pfs_spdk_dev_dio_aligned(pfs_spdk_dev_t *dkdev, uint64_t val)
{
    return (val & (dkdev->dk_sectsz-1)) == 0;
}

static inline void
pfs_spdk_dev_enq_inflight_io(pfs_spdk_ioq_t *dkioq, pfs_devio_t *io)
{
    TAILQ_INSERT_TAIL(&dkioq->dkq_inflight_queue, io, io_next);
    dkioq->dkq_inflight_count++;
}

static inline void
pfs_spdk_dev_deq_inflight_io(pfs_spdk_ioq_t *dkioq, pfs_devio_t *io)
{
    TAILQ_REMOVE(&dkioq->dkq_inflight_queue, io, io_next);
    dkioq->dkq_inflight_count--;
}

static inline void
pfs_spdk_dev_enq_complete_io(pfs_spdk_ioq_t *dkioq, pfs_devio_t *io)
{
    TAILQ_INSERT_TAIL(&dkioq->dkq_complete_queue, io, io_next);
    dkioq->dkq_complete_count++;
}

static inline void
pfs_spdk_dev_deq_complete_io(pfs_spdk_ioq_t *dkioq, pfs_devio_t *io)
{
    TAILQ_REMOVE(&dkioq->dkq_complete_queue, io, io_next);
    dkioq->dkq_complete_count--;
}

static void
pfs_spdk_dev_io_done(struct spdk_bdev_io *bdev_io,
    bool success, void *cb_arg)                                                  
{
    pfs_spdk_iocb_t *iocb = (pfs_spdk_iocb_t *)cb_arg;
    pfs_spdk_iocb_t *tmp = NULL;
    pfs_devio_t *io = iocb->cb_pfs_io;
    pfs_spdk_ioq_t *dkioq = iocb->cb_ioq;

    PFS_ASSERT(io->io_error == PFSDEV_IO_DFTERR);
    io->io_error = success ? 0 : -EIO;
    io->io_private = nullptr;

    iocb->cb_dev->dk_jobs--;
    tmp = __atomic_load_n(&dkioq->dkq_done_q, __ATOMIC_RELAXED);
    for (;;) {
        iocb->cb_next = tmp;
        if (__atomic_compare_exchange_n(&dkioq->dkq_done_q, &tmp, iocb,
                false, __ATOMIC_RELEASE, __ATOMIC_RELAXED)) {
            break;
        }
    }

    /* This works like WIN32 event, we don't repeatly set semaphore */
    pfs_event_set(&dkioq->dkq_done_ev);
    spdk_bdev_free_io(bdev_io);
}

static int
pfs_spdk_dev_io_prep_pread(pfs_spdk_dev_t *dkdev, pfs_devio_t *io,
    pfs_spdk_iocb_t *iocb)
{
    static struct timeval last;

    PFS_ASSERT(pfs_spdk_dev_dio_aligned(dkdev, io->io_bda));
    PFS_ASSERT(pfs_spdk_dev_dio_aligned(dkdev, io->io_len));

    if (FLAGS_pfs_spdk_driver_auto_dma &&
        !(io->io_flags & IO_DMABUF)) {
        iocb->cb_dma_buf = pfs_dma_malloc(BUF_TYPE, dkdev->dk_base.d_buf_align,
            io->io_len, SOCKET_ID_ANY);
        if (iocb->cb_dma_buf == NULL) {
            struct timeval tv = error_time_interval;
            if (pfs_ratecheck(&last, &tv)) {
                pfs_etrace("can not allocate dma mem:%s", __func__);
            }
            return -ENOBUFS;
        }
    } else {
        iocb->cb_dma_buf = NULL;
    }
    iocb->cb_io_done = pfs_spdk_dev_io_fini_pread;
    return 0;
}

static void
pfs_spdk_dev_io_pread(void *arg)
{
    pfs_spdk_iocb_t *iocb = (pfs_spdk_iocb_t *)arg;
    pfs_spdk_dev_t *dkdev;
    pfs_devio_t *io;
    int rc;

    dkdev = iocb->cb_dev;
    io = iocb->cb_pfs_io;
    if (iocb->cb_dma_buf) {
        rc = spdk_bdev_read(dkdev->dk_desc, dkdev->dk_ioch, iocb->cb_dma_buf,
            io->io_bda, io->io_len, pfs_spdk_dev_io_done, iocb);
    } else {
        rc = spdk_bdev_readv(dkdev->dk_desc, dkdev->dk_ioch, io->io_iov,
            io->io_iovcnt, io->io_bda, io->io_len, pfs_spdk_dev_io_done, iocb);
    }
    if (rc == ENOMEM) {
        iocb->cb_bdev_io_wait.bdev = dkdev->dk_bdev;
        iocb->cb_bdev_io_wait.cb_fn = pfs_spdk_dev_io_pread;
        iocb->cb_bdev_io_wait.cb_arg = iocb;
        spdk_bdev_queue_io_wait(dkdev->dk_bdev, dkdev->dk_ioch,
                                &iocb->cb_bdev_io_wait);
    } else if (rc) {
        pfs_etrace("%s error while reading from bdev: %d\n",
            spdk_strerror(-rc), rc);
        if (iocb->cb_dma_buf) {
            pfs_dma_free(iocb->cb_dma_buf);
        }
        abort();
    }
}

static void
pfs_spdk_dev_io_fini_pread(void *arg)
{
    pfs_spdk_iocb_t *iocb = (pfs_spdk_iocb_t *)arg;
    pfs_devio_t *io = iocb->cb_pfs_io;
    pfs_spdk_ioq_t *dkioq = (pfs_spdk_ioq_t *)io->io_queue;
    if (io->io_error == 0 && !(io->io_flags & IO_DMABUF) && iocb->cb_dma_buf) {
        pfs_copy_from_buf_to_iovec(io->io_iov, iocb->cb_dma_buf, io->io_len);
    }
    pfs_spdk_dev_deq_inflight_io(dkioq, io);
    pfs_spdk_dev_enq_complete_io(dkioq, io);

    if (iocb->cb_dma_buf)
        pfs_dma_free(iocb->cb_dma_buf);
    pfs_spdk_dev_free_iocb(iocb);
}

static int
pfs_spdk_dev_io_prep_pwrite(pfs_spdk_dev_t *dkdev, pfs_devio_t *io,
    pfs_spdk_iocb_t *iocb)
{
    static struct timeval last;
    int rc;

    PFS_ASSERT(pfs_spdk_dev_dio_aligned(dkdev, io->io_bda));
    PFS_ASSERT(pfs_spdk_dev_dio_aligned(dkdev, io->io_len));

    if (FLAGS_pfs_spdk_driver_auto_dma &&
        !(io->io_flags & IO_DMABUF) && !(io->io_flags & IO_ZERO)) {
        iocb->cb_dma_buf = pfs_dma_malloc(BUF_TYPE, dkdev->dk_base.d_buf_align,
		   io->io_len, SOCKET_ID_ANY);
        if (iocb->cb_dma_buf == NULL) {
            struct timeval tv = error_time_interval;
            if (pfs_ratecheck(&last, &tv)) {
                pfs_etrace("can not allocate dma mem:%s", __func__);
            }
            return -ENOBUFS;
        }
        pfs_copy_from_iovec_to_buf(iocb->cb_dma_buf, io->io_iov, io->io_len);
    } else {
        iocb->cb_dma_buf = NULL;
    }
    iocb->cb_io_done = pfs_spdk_dev_io_fini_pwrite;
    return 0;
}

static void
pfs_spdk_dev_io_pwrite(void *arg)
{
    pfs_spdk_iocb_t *iocb = (pfs_spdk_iocb_t *)arg;
    pfs_spdk_dev_t *dkdev;
    pfs_devio_t *io;
    int rc;

    dkdev = iocb->cb_dev;
    io = iocb->cb_pfs_io;
    if (io->io_flags & IO_ZERO) {
    	rc = spdk_bdev_write_zeroes(dkdev->dk_desc, dkdev->dk_ioch,
            io->io_bda, io->io_len, pfs_spdk_dev_io_done, iocb);
    } else if (iocb->cb_dma_buf) {
    	rc = spdk_bdev_write(dkdev->dk_desc, dkdev->dk_ioch, iocb->cb_dma_buf,
        	io->io_bda, io->io_len, pfs_spdk_dev_io_done, iocb);
    } else {
	    rc = spdk_bdev_writev(dkdev->dk_desc, dkdev->dk_ioch, io->io_iov,
            io->io_iovcnt, io->io_bda, io->io_len, pfs_spdk_dev_io_done, iocb);
    }
    if (rc == ENOMEM) {
        iocb->cb_bdev_io_wait.bdev = dkdev->dk_bdev;
        iocb->cb_bdev_io_wait.cb_fn = pfs_spdk_dev_io_pwrite;
        iocb->cb_bdev_io_wait.cb_arg = iocb;
        spdk_bdev_queue_io_wait(dkdev->dk_bdev, dkdev->dk_ioch,
                                &iocb->cb_bdev_io_wait);
    } else if (rc) {
        pfs_etrace("%s error while writting to bdev: %d, ioflags=%x",
            spdk_strerror(-rc), rc, io->io_flags);
        if (iocb->cb_dma_buf)
            pfs_dma_free(iocb->cb_dma_buf);
        abort();
    }
}

static void
pfs_spdk_dev_io_fini_pwrite(void *arg)
{
    pfs_spdk_iocb_t *iocb = (pfs_spdk_iocb_t *)arg;
    pfs_devio_t *io = iocb->cb_pfs_io;
    pfs_spdk_ioq_t *dkioq = (pfs_spdk_ioq_t *)io->io_queue;
    pfs_spdk_dev_deq_inflight_io(dkioq, io);
    pfs_spdk_dev_enq_complete_io(dkioq, io);

    if (iocb->cb_dma_buf)
        pfs_dma_free(iocb->cb_dma_buf);
    pfs_spdk_dev_free_iocb(iocb);
}

static int
pfs_spdk_dev_io_prep_trim(pfs_spdk_dev_t *dkdev, pfs_devio_t *io,
    pfs_spdk_iocb_t *iocb)
{
    int rc;

    PFS_ASSERT(pfs_spdk_dev_dio_aligned(dkdev, io->io_bda));
    PFS_ASSERT(pfs_spdk_dev_dio_aligned(dkdev, io->io_len));

    iocb->cb_io_done = pfs_spdk_dev_io_fini_trim;
    return 0;
}

static void
pfs_spdk_dev_io_trim(void *arg)
{
    pfs_spdk_iocb_t *iocb = (pfs_spdk_iocb_t *)arg;
    pfs_spdk_dev_t *dkdev;
    pfs_devio_t *io;
    int rc;

    dkdev = iocb->cb_dev;
    io = iocb->cb_pfs_io;
    rc = spdk_bdev_unmap(dkdev->dk_desc, dkdev->dk_ioch, io->io_bda,
            io->io_len, pfs_spdk_dev_io_done, iocb);
     if (rc == ENOMEM) {
        iocb->cb_bdev_io_wait.bdev = dkdev->dk_bdev;
        iocb->cb_bdev_io_wait.cb_fn = pfs_spdk_dev_io_trim;
        iocb->cb_bdev_io_wait.cb_arg = iocb;
        spdk_bdev_queue_io_wait(dkdev->dk_bdev, dkdev->dk_ioch,
                                &iocb->cb_bdev_io_wait);
    } else if (rc) {
        pfs_etrace("%s error while trimming bdev: %d\n",
            spdk_strerror(-rc), rc);
        abort();
    }
}

static void
pfs_spdk_dev_io_fini_trim(void *arg)
{
    pfs_spdk_iocb_t *iocb = (pfs_spdk_iocb_t *)arg;
    pfs_devio_t *io = iocb->cb_pfs_io;
    pfs_spdk_ioq_t *dkioq = (pfs_spdk_ioq_t *)io->io_queue;
    pfs_spdk_dev_deq_inflight_io(dkioq, io);
    pfs_spdk_dev_enq_complete_io(dkioq, io);
    pfs_spdk_dev_free_iocb(iocb);
}

static int
pfs_spdk_dev_io_prep_flush(pfs_spdk_dev_t *dkdev, pfs_devio_t *io,
    pfs_spdk_iocb_t *iocb)
{
    int rc;

    PFS_ASSERT(pfs_spdk_dev_dio_aligned(dkdev, io->io_bda));
    PFS_ASSERT(pfs_spdk_dev_dio_aligned(dkdev, io->io_len));

    iocb->cb_io_done = pfs_spdk_dev_io_fini_flush;
    return 0;
}

static void
pfs_spdk_dev_io_flush(void *arg)
{
    pfs_spdk_iocb_t *iocb = (pfs_spdk_iocb_t *)arg;
    pfs_spdk_dev_t *dkdev;
    int rc;

    dkdev = iocb->cb_dev;
    rc = spdk_bdev_flush(dkdev->dk_desc, dkdev->dk_ioch, 0, dkdev->dk_size,
            pfs_spdk_dev_io_done, iocb);
    if (rc == ENOMEM) {
        iocb->cb_bdev_io_wait.bdev = dkdev->dk_bdev;
        iocb->cb_bdev_io_wait.cb_fn = pfs_spdk_dev_io_flush;
        iocb->cb_bdev_io_wait.cb_arg = iocb;
        spdk_bdev_queue_io_wait(dkdev->dk_bdev, dkdev->dk_ioch,
                                &iocb->cb_bdev_io_wait);
    } else if (rc) {
        pfs_etrace("%s error while flushing bdev: %d\n", 
            spdk_strerror(-rc), rc);
        abort();
    }
}

static void
pfs_spdk_dev_io_fini_flush(void *arg)
{
    pfs_spdk_iocb_t *iocb = (pfs_spdk_iocb_t *)arg;
    pfs_devio_t *io = iocb->cb_pfs_io;
    pfs_spdk_ioq_t *dkioq = (pfs_spdk_ioq_t *)io->io_queue;
    pfs_spdk_dev_deq_inflight_io(dkioq, io);
    pfs_spdk_dev_enq_complete_io(dkioq, io);
    pfs_spdk_dev_free_iocb(iocb);
}

static void
pfs_spdk_dev_send_iocb(pfs_spdk_dev_t *dkdev,
    spdk_msg_fn fn,
    pfs_spdk_iocb_t *iocb)
{
    pfs_spdk_iocb_t *head;
    int count;

    iocb->cb_io_op = fn;
    head = __atomic_load_n(&dkdev->dk_incoming, __ATOMIC_RELAXED);
    for (;;) {
        iocb->cb_next = head;
        if (__atomic_compare_exchange_n(&dkdev->dk_incoming, &head, iocb,
                true, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
            break;
        }
        rte_pause();
    }

    if (FLAGS_pfs_spdk_driver_poll_delay != 0) {
        sem_getvalue(&dkdev->dk_sem, &count);
        if (!count)
            sem_post(&dkdev->dk_sem);
    }
}

static void
pfs_spdk_dev_pull_iocb(pfs_spdk_dev_t *dkdev)
{
    pfs_spdk_iocb_t *prev, *curr, *next = NULL;

    curr = __atomic_load_n(&dkdev->dk_incoming, __ATOMIC_RELAXED);
    if (curr == NULL)
        return;
    curr = __atomic_exchange_n(&dkdev->dk_incoming, NULL, __ATOMIC_ACQUIRE);
    /* reverse the list */
    if (curr != NULL) {
        for (;;) {
            prev = curr->cb_next; 
            curr->cb_next = next;
            if (prev == NULL)
                break;
            next = curr;
            curr = prev;
        }
    }

    while (curr != NULL) {
        dkdev->dk_jobs++;
        next = curr->cb_next;
        curr->cb_io_op(curr);
        curr = next;
    }
}

static int
pfs_spdk_dev_submit_io(pfs_dev_t *dev, pfs_ioq_t *ioq, pfs_devio_t *io)
{   
    pfs_spdk_dev_t *dkdev = (pfs_spdk_dev_t *)dev;
    pfs_spdk_ioq_t *dkioq = (pfs_spdk_ioq_t *)ioq;
    pfs_spdk_iocb_t *iocb = nullptr;
    spdk_msg_fn fn = nullptr;
    int err = 0, count = 0;

    iocb = pfs_spdk_dev_alloc_iocb();
    if (iocb == NULL) {
        return -ENOBUFS;
    }
    iocb->cb_pfs_io = io;
    iocb->cb_ioq = dkioq;
    iocb->cb_dev = dkdev;
    io->io_private = iocb;
    io->io_error = PFSDEV_IO_DFTERR;
    pfs_spdk_dev_enq_inflight_io(dkioq, io);

    switch (io->io_op) {
    case PFSDEV_REQ_RD:
        err = pfs_spdk_dev_io_prep_pread(dkdev, io, iocb);
        if (err)
            goto fail;
        fn = pfs_spdk_dev_io_pread;
        break;
    case PFSDEV_REQ_WR:
        err = pfs_spdk_dev_io_prep_pwrite(dkdev, io, iocb);
        if (err)
            goto fail;
        fn = pfs_spdk_dev_io_pwrite;
        break;
    case PFSDEV_REQ_TRIM:
        err = pfs_spdk_dev_io_prep_trim(dkdev, io, iocb);
        if (err)
            goto fail;
        fn = pfs_spdk_dev_io_trim;
        break;
    case PFSDEV_REQ_FLUSH:
        err = pfs_spdk_dev_io_prep_flush(dkdev, io, iocb);
        if (err)
            goto fail;
        fn = pfs_spdk_dev_io_flush;
        break;

    default:
        err = EINVAL;
        pfs_etrace("invalid io task! op: %d, bufp: %p, len: %zu, bda%lu\n",
            io->io_op, io->io_buf, io->io_len, io->io_bda);
        PFS_ASSERT("unsupported io type" == NULL);
    }

    pfs_spdk_dev_send_iocb(dkdev, fn, iocb);
    if (err) {
fail:
        /* io submit failure */
        pfs_spdk_dev_deq_inflight_io(dkioq, io);
        io->io_private = nullptr;
        io->io_error = err;
        pfs_spdk_dev_free_iocb(iocb);
        return err;
    }

    return 0;
}

static pfs_devio_t *
pfs_spdk_dev_wait_io(pfs_dev_t *dev, pfs_ioq_t *ioq, pfs_devio_t *io)
{
    struct pfs_spdk_iocb *iocb, *next;
    pfs_spdk_dev_t *dkdev = (pfs_spdk_dev_t *)dev;
    pfs_spdk_ioq_t *dkioq = (pfs_spdk_ioq_t *)ioq;
    pfs_devio_t *nio = nullptr;

    while ((dkioq->dkq_inflight_count | dkioq->dkq_complete_count)) {
        TAILQ_FOREACH(nio, &dkioq->dkq_complete_queue, io_next) {
            if (io == nullptr || nio == io)
                break;
        }
        if (nio == nullptr) {
            if (!dkioq->dkq_inflight_count) {
                pfs_etrace("inflight is empty\n");
                break;
            }

            pfs_event_wait(&dkioq->dkq_done_ev);

            for (iocb = __atomic_exchange_n(&dkioq->dkq_done_q, NULL,
                    __ATOMIC_ACQUIRE); iocb; iocb = next) {
                next = iocb->cb_next;
                iocb->cb_io_done(iocb);
            }
        } else {
            pfs_spdk_dev_deq_complete_io(dkioq, nio);
            break;
        }
    }
    return nio;
}

static int
pfs_spdk_dev_has_cache(pfs_dev_t *dev)
{
    pfs_spdk_dev_t *dkdev = (pfs_spdk_dev_t *)dev;
    return dkdev->dk_has_cache;
}

void
pfsdev_exit_thread_spdk_drv(void)
{
    pfs_spdk_iocb *iocb;

    while ((iocb = SLIST_FIRST(&tls_free_iocb))) {
        SLIST_REMOVE_HEAD(&tls_free_iocb, cb_free);
        pfs_mem_free(iocb, M_SPDK_IOCB);
    }
}

struct pfs_devops pfs_spdk_dev_ops = {
    .dop_name           = "spdk",
    .dop_type           = PFS_DEV_SPDK,
    .dop_size           = sizeof(pfs_spdk_dev_t),
    .dop_memtag         = M_SPDK_DEV,
    .dop_open           = pfs_spdk_dev_open,
    .dop_reopen         = pfs_spdk_dev_reopen,
    .dop_close          = pfs_spdk_dev_close,
    .dop_info           = pfs_spdk_dev_info,
    .dop_reload         = pfs_spdk_dev_reload,
    .dop_create_ioq     = pfs_spdk_dev_create_ioq,
    .dop_need_throttle  = pfs_spdk_dev_need_throttle,
    .dop_submit_io      = pfs_spdk_dev_submit_io,
    .dop_wait_io        = pfs_spdk_dev_wait_io,
    .dop_has_cache      = pfs_spdk_dev_has_cache
};
