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

#include <spdk/env.h>
#include <spdk/log.h>
#include <spdk/string.h>
#include <dpdk/rte_memcpy.h>
#include <common/buf_ring.h>

#include "pfs_trace.h"
#include "pfs_devio.h"
#include "pfs_memory.h"
#include "pfs_option.h"
#include "pfs_impl.h"
#include "pfs_spdk.h"

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
    pthread_t   dk_pthread;
    struct pfs_spdk_thread *dk_thread;
    struct spdk_io_channel *dk_ch;
    int         dk_stop;
    char        dk_path[128];
    sem_t       dk_sem;
    int         dk_jobs;
} pfs_spdk_dev_t;

typedef struct pfs_spdk_iocb {
    pfs_devio_t            *pfs_io;
    void                   *dma_buf;
    pfs_spdk_dev_t         *dev;
    struct pfs_spdk_thread *src_thread;
    struct spdk_bdev_io_wait_entry bdev_io_wait;
    spdk_msg_fn io_done;
    struct pfs_spdk_ioq *ioq;
} pfs_spdk_iocb_t;

typedef struct pfs_spdk_ioq {
    /* must be first member */
    pfs_ioq_t   dkq_ioq;
#define dkq_destroy     dkq_ioq.ioq_destroy

    int         dkq_inflight_count;
    int         dkq_complete_count;
    TAILQ_HEAD(, pfs_devio) dkq_inflight_queue;
    TAILQ_HEAD(, pfs_devio) dkq_complete_queue;
    struct buf_ring *dkq_done_q;
    sem_t       dkq_done_sem;
} pfs_spdk_ioq_t;

struct bdev_open_param {
    pfs_spdk_dev_t *dkdev;
    sem_t sem;
    int rc;
};

static const int64_t g_iodepth = 128;

static void pfs_spdk_dev_io_fini_pread(void *iocb);
static void pfs_spdk_dev_io_fini_pwrite(void *iocb);
static void pfs_spdk_dev_io_fini_trim(void *iocb);
static void pfs_spdk_dev_io_fini_flush(void *iocb);

static void
pfs_spdk_dev_destroy_ioq(pfs_ioq_t *ioq)
{
    pfs_spdk_ioq_t *dkioq = (pfs_spdk_ioq_t *)ioq;
    int err;

    PFS_ASSERT(dkioq->dkq_inflight_count == 0);
    PFS_ASSERT(TAILQ_EMPTY(&dkioq->dkq_inflight_queue));

    PFS_ASSERT(dkioq->dkq_complete_count == 0);
    PFS_ASSERT(TAILQ_EMPTY(&dkioq->dkq_complete_queue));

    buf_ring_free(dkioq->dkq_done_q);
    sem_destroy(&dkioq->dkq_done_sem);
    pfs_mem_free(dkioq, M_SPDK_DEV_IOQ);
}

static pfs_ioq_t *
pfs_spdk_dev_create_ioq(pfs_dev_t *dev)
{
    pfs_spdk_ioq_t *dkioq;
    void *p;
    int err;

    err = pfs_mem_memalign(&p, 64, sizeof(*dkioq), M_SPDK_DEV_IOQ);
    if (err) {
        pfs_etrace("create disk ioq failed: %d, %s\n", strerror(err));
        return NULL;
    }
    dkioq = (pfs_spdk_ioq_t *)p;
    dkioq->dkq_destroy = pfs_spdk_dev_destroy_ioq;
    dkioq->dkq_inflight_count = 0;
    dkioq->dkq_complete_count = 0;
    TAILQ_INIT(&dkioq->dkq_inflight_queue);
    TAILQ_INIT(&dkioq->dkq_complete_queue);
    dkioq->dkq_done_q = buf_ring_alloc(g_iodepth);
    if (dkioq->dkq_done_q == NULL) {
        pfs_etrace("create buf_ring failed, ENOMEM\n");
	    pfs_mem_free(p, M_SPDK_DEV_IOQ);
	    return NULL;
    }
    sem_init(&dkioq->dkq_done_sem, 0, 0);
    return (pfs_ioq_t *)dkioq;
}

static bool
pfs_spdk_dev_need_throttle(pfs_dev_t *dev, pfs_ioq_t *ioq)
{
    pfs_spdk_ioq_t *dkioq = (pfs_spdk_ioq_t *)ioq;
    return (dkioq->dkq_inflight_count >= g_iodepth-10);
}

static void
bdev_event_cb(enum spdk_bdev_event_type type, struct spdk_bdev *bdev,
    void *event_ctx)
{
    pfs_etrace("Unsupported spdk bdev event: type %d\n", type);
    return;
}

static void *
bdev_thread_msg_loop(void *arg)
{
    struct pfs_spdk_thread *thread = pfs_current_spdk_thread();
    struct bdev_open_param *param = (struct bdev_open_param *)arg;
    pfs_spdk_dev_t *dkdev = param->dkdev;
    pfs_dev_t *dev = &dkdev->dk_base;
    int err;

    err = spdk_bdev_open_ext(dev->d_devname, dev_writable(dev),
                             bdev_event_cb, dkdev, &dkdev->dk_desc);
    if (err) {
        pfs_etrace("can not open spdk device %s, %s\n", dev->d_devname,
                   strerror(err));
err_exit:
        param->rc = err;
        sem_post(&param->sem);
        return NULL;
    }
    dkdev->dk_bdev = spdk_bdev_desc_get_bdev(dkdev->dk_desc);
    dkdev->dk_ch = pfs_get_spdk_io_channel(dkdev->dk_desc);
    if (dkdev->dk_ch == NULL) {
        pfs_etrace("can nnot get io channel of spdk device: %s\n",
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
    pfs_itrace("spdk device: '%s', block_num:%ld, "
               "block_size: %d, write_unit_size: %d, has_cache: %d\n",
               dev->d_devname, dkdev->dk_block_num, dkdev->dk_block_size,
               dkdev->dk_unit_size, dkdev->dk_has_cache);

    param->rc = 0;
    sem_post(&param->sem);

    struct spdk_thread *spdk_thread = thread->spdk_thread;
    while (!dkdev->dk_stop) {
        while (__atomic_load_n(&dkdev->dk_jobs, __ATOMIC_RELAXED)) {
            spdk_thread_poll(spdk_thread, 0, spdk_get_ticks());
        }
 
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 1;
        sem_timedwait(&dkdev->dk_sem, &ts);
    }
 
    pfs_put_spdk_io_channel(dkdev->dk_ch);
    spdk_bdev_close(dkdev->dk_desc);

    while (spdk_thread_poll(spdk_thread, 0, 0))
        {}
    return NULL;
}

static int
pfs_spdk_dev_open(pfs_dev_t *dev)
{
    pfs_spdk_dev_t *dkdev = (pfs_spdk_dev_t *)dev;
    struct spdk_thread *origin, *thread;
    struct bdev_open_param param;
    int err;

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

static void
pfs_spdk_dev_enq_inflight_io(pfs_spdk_ioq_t *dkioq, pfs_devio_t *io)
{
    TAILQ_INSERT_TAIL(&dkioq->dkq_inflight_queue, io, io_next);
    dkioq->dkq_inflight_count++;
}

static void
pfs_spdk_dev_deq_inflight_io(pfs_spdk_ioq_t *dkioq, pfs_devio_t *io)
{
    TAILQ_REMOVE(&dkioq->dkq_inflight_queue, io, io_next);
    dkioq->dkq_inflight_count--;
}

static void
pfs_spdk_dev_enq_complete_io(pfs_spdk_ioq_t *dkioq, pfs_devio_t *io)
{
    TAILQ_INSERT_TAIL(&dkioq->dkq_complete_queue, io, io_next);
    dkioq->dkq_complete_count++;
}

static void
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
    pfs_devio_t *io = iocb->pfs_io;
    pfs_spdk_ioq_t *dkioq = iocb->ioq;
    int err;

    PFS_ASSERT(io->io_error == PFSDEV_IO_DFTERR);
    io->io_error = success ? 0 : -EIO;
    io->io_private = nullptr;

    __atomic_sub_fetch(&iocb->dev->dk_jobs, 1, __ATOMIC_RELAXED);
    buf_ring_enqueue(dkioq->dkq_done_q, iocb);
    sem_post(&dkioq->dkq_done_sem);
    spdk_bdev_free_io(bdev_io);
}

static int
pfs_spdk_dev_io_prep_pread(pfs_spdk_dev_t *dkdev, pfs_devio_t *io,
    pfs_spdk_iocb_t *iocb)
{
    PFS_ASSERT(pfs_spdk_dev_dio_aligned(dkdev, io->io_bda));
    PFS_ASSERT(pfs_spdk_dev_dio_aligned(dkdev, io->io_len));

    iocb->dma_buf = spdk_dma_malloc(io->io_len, 4096, NULL);
    if (iocb->dma_buf == NULL) {
        return -ENOMEM;
    }
    iocb->io_done = pfs_spdk_dev_io_fini_pread;
    return 0;
}

static void
pfs_spdk_dev_io_pread(void *arg)
{
    pfs_spdk_iocb_t *iocb = (pfs_spdk_iocb_t *)arg;
    pfs_spdk_dev_t *dkdev;
    pfs_devio_t *io;
    int rc;

    dkdev = iocb->dev;
    io = iocb->pfs_io;
    rc = spdk_bdev_read(dkdev->dk_desc, dkdev->dk_ch, iocb->dma_buf,
        io->io_bda, io->io_len, pfs_spdk_dev_io_done, iocb);
    if (rc == ENOMEM) {
        iocb->bdev_io_wait.bdev = dkdev->dk_bdev;
        iocb->bdev_io_wait.cb_fn = pfs_spdk_dev_io_pread;
        iocb->bdev_io_wait.cb_arg = iocb;
        spdk_bdev_queue_io_wait(dkdev->dk_bdev, dkdev->dk_ch,
                                &iocb->bdev_io_wait);
    } else if (rc) {
        spdk_dma_free(iocb->dma_buf);
        SPDK_ERRLOG("%s error while reading from bdev: %d\n", 
            spdk_strerror(-rc), rc);
        abort();
    }
}

static void
pfs_spdk_dev_io_fini_pread(void *arg)
{
    pfs_spdk_iocb_t *iocb = (pfs_spdk_iocb_t *)arg;
    pfs_devio_t *io = iocb->pfs_io;
    pfs_spdk_ioq_t *dkioq = (pfs_spdk_ioq_t *)io->io_queue;
    if (io->io_error == 0) {
            rte_memcpy(io->io_buf, iocb->dma_buf, io->io_len);
    }
    pfs_spdk_dev_deq_inflight_io(dkioq, io);
    pfs_spdk_dev_enq_complete_io(dkioq, io);

    spdk_dma_free(iocb->dma_buf);
    free(iocb);
}

static int
pfs_spdk_dev_io_prep_pwrite(pfs_spdk_dev_t *dkdev, pfs_devio_t *io,
    pfs_spdk_iocb_t *iocb)
{
    int rc;

    PFS_ASSERT(pfs_spdk_dev_dio_aligned(dkdev, io->io_bda));
    PFS_ASSERT(pfs_spdk_dev_dio_aligned(dkdev, io->io_len));

    iocb->dma_buf = spdk_dma_malloc(io->io_len, 4096, NULL);
    if (iocb->dma_buf == NULL) {
        return -ENOMEM;
    }
    rte_memcpy(iocb->dma_buf, io->io_buf, io->io_len);
    iocb->io_done = pfs_spdk_dev_io_fini_pwrite;
    return 0;
}

static void
pfs_spdk_dev_io_pwrite(void *arg)
{
    pfs_spdk_iocb_t *iocb = (pfs_spdk_iocb_t *)arg;
    pfs_spdk_dev_t *dkdev;
    pfs_devio_t *io;
    int rc;

    dkdev = iocb->dev;
    io = iocb->pfs_io;
    rc = spdk_bdev_write(dkdev->dk_desc, dkdev->dk_ch, iocb->dma_buf, io->io_bda,
              io->io_len, pfs_spdk_dev_io_done, iocb);
    if (rc == ENOMEM) {
        iocb->bdev_io_wait.bdev = dkdev->dk_bdev;
        iocb->bdev_io_wait.cb_fn = pfs_spdk_dev_io_pwrite;
        iocb->bdev_io_wait.cb_arg = iocb;
        spdk_bdev_queue_io_wait(dkdev->dk_bdev, dkdev->dk_ch,
                                &iocb->bdev_io_wait);
    } else if (rc) {
        SPDK_ERRLOG("%s error while writting to bdev: %d\n", 
            spdk_strerror(-rc), rc);
        spdk_dma_free(iocb->dma_buf);
        abort();
    }
}

static void
pfs_spdk_dev_io_fini_pwrite(void *arg)
{
    pfs_spdk_iocb_t *iocb = (pfs_spdk_iocb_t *)arg;
    pfs_devio_t *io = iocb->pfs_io;
    pfs_spdk_ioq_t *dkioq = (pfs_spdk_ioq_t *)io->io_queue;
    pfs_spdk_dev_deq_inflight_io(dkioq, io);
    pfs_spdk_dev_enq_complete_io(dkioq, io);

    spdk_dma_free(iocb->dma_buf);
    free(iocb);
}

static int
pfs_spdk_dev_io_prep_trim(pfs_spdk_dev_t *dkdev, pfs_devio_t *io,
    pfs_spdk_iocb_t *iocb)
{
    int rc;

    PFS_ASSERT(pfs_spdk_dev_dio_aligned(dkdev, io->io_bda));
    PFS_ASSERT(pfs_spdk_dev_dio_aligned(dkdev, io->io_len));

    iocb->io_done = pfs_spdk_dev_io_fini_trim;
    return 0;
}

static void
pfs_spdk_dev_io_trim(void *arg)
{
    pfs_spdk_iocb_t *iocb = (pfs_spdk_iocb_t *)arg;
    pfs_spdk_dev_t *dkdev;
    pfs_devio_t *io;
    int rc;

    dkdev = iocb->dev;
    io = iocb->pfs_io;
    rc = spdk_bdev_unmap(dkdev->dk_desc, dkdev->dk_ch, io->io_bda, io->io_len,
            pfs_spdk_dev_io_done, iocb);                 
     if (rc == ENOMEM) {
        iocb->bdev_io_wait.bdev = dkdev->dk_bdev;
        iocb->bdev_io_wait.cb_fn = pfs_spdk_dev_io_trim;
        iocb->bdev_io_wait.cb_arg = iocb;
        spdk_bdev_queue_io_wait(dkdev->dk_bdev, dkdev->dk_ch,
                                &iocb->bdev_io_wait);
    } else if (rc) {
        SPDK_ERRLOG("%s error while trimming bdev: %d\n", 
            spdk_strerror(-rc), rc);
        abort();
    }
}

static void
pfs_spdk_dev_io_fini_trim(void *arg)
{
    pfs_spdk_iocb_t *iocb = (pfs_spdk_iocb_t *)arg;
    pfs_devio_t *io = iocb->pfs_io;
    pfs_spdk_ioq_t *dkioq = (pfs_spdk_ioq_t *)io->io_queue;
    pfs_spdk_dev_deq_inflight_io(dkioq, io);
    pfs_spdk_dev_enq_complete_io(dkioq, io);
    free(iocb);
}

static int
pfs_spdk_dev_io_prep_flush(pfs_spdk_dev_t *dkdev, pfs_devio_t *io,
    pfs_spdk_iocb_t *iocb)
{
    int rc;

    PFS_ASSERT(pfs_spdk_dev_dio_aligned(dkdev, io->io_bda));
    PFS_ASSERT(pfs_spdk_dev_dio_aligned(dkdev, io->io_len));

    iocb->io_done = pfs_spdk_dev_io_fini_flush;
    return 0;
}

static void
pfs_spdk_dev_io_flush(void *arg)
{
    pfs_spdk_iocb_t *iocb = (pfs_spdk_iocb_t *)arg;
    pfs_spdk_dev_t *dkdev;
    int rc;

    dkdev = iocb->dev;
    rc = spdk_bdev_flush(dkdev->dk_desc, dkdev->dk_ch, 0, dkdev->dk_size,
            pfs_spdk_dev_io_done, iocb);
    if (rc == ENOMEM) {
        iocb->bdev_io_wait.bdev = dkdev->dk_bdev;
        iocb->bdev_io_wait.cb_fn = pfs_spdk_dev_io_flush;
        iocb->bdev_io_wait.cb_arg = iocb;
        spdk_bdev_queue_io_wait(dkdev->dk_bdev, dkdev->dk_ch,
                                &iocb->bdev_io_wait);
    } else if (rc) {
        SPDK_ERRLOG("%s error while flushing bdev: %d\n", 
            spdk_strerror(-rc), rc);
        abort();
    }
}

static void
pfs_spdk_dev_io_fini_flush(void *arg)
{
    pfs_spdk_iocb_t *iocb = (pfs_spdk_iocb_t *)arg;
    pfs_devio_t *io = iocb->pfs_io;
    pfs_spdk_ioq_t *dkioq = (pfs_spdk_ioq_t *)io->io_queue;
    pfs_spdk_dev_deq_inflight_io(dkioq, io);
    pfs_spdk_dev_enq_complete_io(dkioq, io);
    free(iocb);
}

static int
pfs_spdk_dev_submit_io(pfs_dev_t *dev, pfs_ioq_t *ioq, pfs_devio_t *io)
{   
    pfs_spdk_dev_t *dkdev = (pfs_spdk_dev_t *)dev;
    pfs_spdk_ioq_t *dkioq = (pfs_spdk_ioq_t *)ioq;
    pfs_spdk_iocb_t *iocb = nullptr;
    spdk_msg_fn fn = nullptr;
    int err = 0, count = 0;

    iocb = (pfs_spdk_iocb_t *)calloc(1, sizeof(pfs_spdk_iocb_t));
    iocb->pfs_io = io;
    iocb->ioq = dkioq;
    iocb->dev = dkdev;
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

    __atomic_fetch_add(&dkdev->dk_jobs, 1, __ATOMIC_RELAXED);
    err = spdk_thread_send_msg(dkdev->dk_thread->spdk_thread, fn, iocb);
    while (err == -ENOMEM) {
        pfs_etrace("%s spdk_thread_send_msg failed, retrying\n", __func__);
        usleep(1000);
        err = spdk_thread_send_msg(dkdev->dk_thread->spdk_thread, fn, iocb);
    }
    __atomic_thread_fence(__ATOMIC_ACQ_REL);
    sem_getvalue(&dkdev->dk_sem, &count);
    if (!count)
        sem_post(&dkdev->dk_sem);

    if (err) {
fail:
        /* io submit failure */
        pfs_spdk_dev_deq_inflight_io(dkioq, io);
        io->io_private = nullptr;
        io->io_error = err;
        free(iocb);

        pfs_etrace("failed to prep iocb\n");
        return err;
    }

    return 0;
}

static pfs_devio_t *
pfs_spdk_dev_wait_io(pfs_dev_t *dev, pfs_ioq_t *ioq, pfs_devio_t *io)
{
    struct pfs_spdk_iocb *iocb;
    pfs_spdk_dev_t *dkdev = (pfs_spdk_dev_t *)dev;
    pfs_spdk_ioq_t *dkioq = (pfs_spdk_ioq_t *)ioq;
    pfs_devio_t *nio = nullptr;

    while (!TAILQ_EMPTY(&dkioq->dkq_inflight_queue) ||
           !TAILQ_EMPTY(&dkioq->dkq_complete_queue)) {
        TAILQ_FOREACH(nio, &dkioq->dkq_complete_queue, io_next) {
            if (io == nullptr || nio == io)
                break;
        }
        if (nio == nullptr) {
            if (TAILQ_EMPTY(&dkioq->dkq_inflight_queue)) {
                pfs_etrace("inflight is empty\n");
                break;
            }
            while (-1 == sem_wait(&dkioq->dkq_done_sem) && errno == EINTR) {}
            iocb = (struct pfs_spdk_iocb *)buf_ring_dequeue_sc(dkioq->dkq_done_q);
            iocb->io_done(iocb);
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

