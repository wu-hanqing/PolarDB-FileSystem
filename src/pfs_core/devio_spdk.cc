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

#include <spdk/env.h>
#include <spdk/log.h>
#include <spdk/string.h>
#include <dpdk/rte_memcpy.h>

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
    size_t      dk_sectsz;
    uint64_t    dk_block_num;
    uint32_t    dk_block_size;
    pthread_t   dk_pthread;
    struct spdk_thread *dk_thread;
    int         dk_stop;
    char        dk_path[128];
} pfs_spdk_dev_t;

typedef struct pfs_spdk_iocb {
    pfs_devio_t            *pfs_io;
    void                   *dma_buf;
    struct spdk_io_channel *ch;
    pfs_spdk_dev_t         *dev;
    struct spdk_bdev_io_wait_entry bdev_io_wait;
} pfs_spdk_iocb_t;

typedef struct pfs_spdk_ioq {
    /* must be first member */
    pfs_ioq_t       dkq_ioq;
#define dkq_destroy     dkq_ioq.ioq_destroy

    int         dkq_inflight_count;
    int         dkq_complete_count;
    TAILQ_HEAD(, pfs_devio) dkq_inflight_queue;
    TAILQ_HEAD(, pfs_devio) dkq_complete_queue;
} pfs_spdk_ioq_t;

static int64_t spdk_iodepth = 65536;
PFS_OPTION_REG(spdk_iodepth, pfs_check_ival_normal);

static void
pfs_spdk_dev_destroy_ioq(pfs_ioq_t *ioq)
{
    pfs_spdk_ioq_t *dkioq = (pfs_spdk_ioq_t *)ioq;
    int err;

    PFS_ASSERT(dkioq->dkq_inflight_count == 0);
    PFS_ASSERT(TAILQ_EMPTY(&dkioq->dkq_inflight_queue));

    PFS_ASSERT(dkioq->dkq_complete_count == 0);
    PFS_ASSERT(TAILQ_EMPTY(&dkioq->dkq_complete_queue));

    pfs_mem_free(dkioq, M_SPDK_DEV_IOQ);
}

static pfs_ioq_t *
pfs_spdk_dev_create_ioq(pfs_dev_t *dev)
{
    pfs_spdk_ioq_t *dkioq;
    int err;

    dkioq = (pfs_spdk_ioq_t *)pfs_mem_malloc(sizeof(*dkioq), M_SPDK_DEV_IOQ);
    if (dkioq == NULL) {
        pfs_etrace("create diks ioq data failed: ENOMEM\n");
        return NULL;
    }
    memset(dkioq, 0, sizeof(*dkioq));
    dkioq->dkq_destroy = pfs_spdk_dev_destroy_ioq;
    dkioq->dkq_inflight_count = 0;
    dkioq->dkq_complete_count = 0;
    TAILQ_INIT(&dkioq->dkq_inflight_queue);
    TAILQ_INIT(&dkioq->dkq_complete_queue);

    return (pfs_ioq_t *)dkioq;
}

static bool
pfs_spdk_dev_need_throttle(pfs_dev_t *dev, pfs_ioq_t *ioq)
{
    pfs_spdk_ioq_t *dkioq = (pfs_spdk_ioq_t *)ioq;
    return (dkioq->dkq_inflight_count >= spdk_iodepth);
}

static void
bdev_event_cb(enum spdk_bdev_event_type type, struct spdk_bdev *bdev,
    void *event_ctx)
{
    SPDK_WARNLOG("Unsupported bdev event: type %d\n", type);
    return;
}

static void *
bdev_thread_msg_loop(void *arg)
{
    pfs_spdk_dev_t *dkdev = (pfs_spdk_dev_t *)arg;

    spdk_set_thread(dkdev->dk_thread);
    while (!dkdev->dk_stop) {
        spdk_thread_poll(dkdev->dk_thread, 0, 0);
        usleep(10000);
    }
    spdk_set_thread(NULL);
    return NULL;
}

static int
pfs_spdk_dev_open(pfs_dev_t *dev)
{
    pfs_spdk_dev_t *dkdev = (pfs_spdk_dev_t *)dev;
    struct spdk_thread *origin, *thread;
    int err, sectsz;

    origin = spdk_get_thread();
    thread = spdk_thread_create("bdev_msg_loop", NULL);
    if (thread == NULL) {
        pfs_etrace("can not create spdk thread, %s\n", strerror(errno)); 
        ERR_RETVAL(ENOMEM);
    }
    spdk_set_thread(thread);

    err = spdk_bdev_open_ext(dev->d_devname, dev_writable(dev),
                             bdev_event_cb, dev, &dkdev->dk_desc);
    if (err) {
        spdk_thread_exit(thread);
        while (!spdk_thread_is_exited(thread))
            spdk_thread_poll(thread, 0, 0);
        spdk_thread_destroy(thread);
        spdk_set_thread(origin);
        pfs_etrace("can not open spdk device %s, %s\n", dev->d_devname,
                   strerror(-err)); 
        return err;
    }

    dkdev->dk_bdev = spdk_bdev_desc_get_bdev(dkdev->dk_desc);

    strncpy(dkdev->dk_path, dev->d_devname, sizeof(dkdev->dk_path));
    dkdev->dk_path[sizeof(dkdev->dk_path)-1] = 0;

    sectsz = 4096; //FIXME

    dkdev->dk_stop = 0;
    dkdev->dk_block_num = spdk_bdev_get_num_blocks(dkdev->dk_bdev);
    dkdev->dk_block_size = spdk_bdev_get_block_size(dkdev->dk_bdev);
    dkdev->dk_thread = thread;
    dkdev->dk_sectsz = sectsz;
    spdk_set_thread(origin);

    err = pthread_create(&dkdev->dk_pthread, NULL, bdev_thread_msg_loop, dkdev);
    if (err) {
          pfs_etrace("can not create msg thread %s, %s\n", dev->d_devname,
                   strerror(err));
          abort();
    }

    return 0;
}

static int
pfs_spdk_dev_reopen(pfs_dev_t *dev)
{
    pfs_spdk_dev_t *dkdev = (pfs_spdk_dev_t *)dev;
#if 0
    char path[PATH_MAX], *p;
    int fd, err, sectsz;

    strcpy(path, dev->d_devname);
    p = strstr(path, "@@");
    if (p == NULL) {
	return -EINVAL;
    }
    strcpy(path, p+1);
    path[0] = '/';

    /*
     * RW should guarantee the data is written to disk,
     * while RO should bypass page cache.
     */
    if (dkdev->dk_fd >= 0) {
        g_curve->Close(dkdev->dk_fd);
        dkdev->dk_fd = -1;
    }

    pfs_itrace("reopen curve disk: %s, now d_flags:0x%x", path, dev->d_flags);

    OpenFlags openflags;
    openflags.exclusive = false;
    fd = g_curve->Open(path, openflags);
    if (fd < 0) {
        err = errno;
        pfs_etrace("cant open %s: %s\n", path, strerror(err));
        ERR_RETVAL(err);
    }

    sectsz = 4096; //FIXME

    strcpy(dkdev->dk_path, path);
    dkdev->dk_fd = fd;
    dkdev->dk_sectsz = (size_t)sectsz;
#endif
    return 0;
}

static int
pfs_spdk_dev_close(pfs_dev_t *dev)
{
    struct spdk_thread *origin;
    pfs_spdk_dev_t *dkdev = (pfs_spdk_dev_t *)dev;
    if (dkdev->dk_desc == NULL)
        return 0;
    
    dkdev->dk_stop = 1;
    pthread_join(dkdev->dk_pthread, NULL);

    pfs_spdk_close_all_io_channels(dkdev->dk_desc);

    origin = spdk_get_thread();
    spdk_set_thread(dkdev->dk_thread);
    spdk_bdev_close(dkdev->dk_desc);
    spdk_thread_exit(dkdev->dk_thread);
    while (!spdk_thread_is_exited(dkdev->dk_thread))
        spdk_thread_poll(dkdev->dk_thread, 0, 0);
    spdk_thread_destroy(dkdev->dk_thread);
    dkdev->dk_desc = NULL;
    spdk_set_thread(origin);
    return 0;
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
    pfs_spdk_ioq_t *dkioq = (pfs_spdk_ioq_t *)io->io_queue;

    PFS_ASSERT(io->io_error == PFSDEV_IO_DFTERR);
    io->io_error = success ? 0 : -EIO;
    io->io_private = nullptr;

    if (success) {
        if (io->io_op == PFSDEV_REQ_RD) {
            rte_memcpy(io->io_buf, iocb->dma_buf, io->io_len);
        }
    }

    pfs_spdk_dev_deq_inflight_io(dkioq, io);
    pfs_spdk_dev_enq_complete_io(dkioq, io);

    PFS_ASSERT(0 == pfs_put_spdk_io_channel(iocb->ch));
    spdk_bdev_free_io(bdev_io);
    spdk_dma_free(iocb->dma_buf);
    free(iocb);
}

static int
pfs_spdk_dev_io_prep_pread(pfs_spdk_dev_t *dkdev, pfs_devio_t *io,
    pfs_spdk_iocb_t *iocb)
{
    PFS_ASSERT(pfs_spdk_dev_dio_aligned(dkdev, io->io_bda));
    PFS_ASSERT(pfs_spdk_dev_dio_aligned(dkdev, io->io_len));

    iocb->ch = pfs_get_spdk_io_channel(dkdev->dk_desc);
    if (iocb->ch == NULL)
	    return -EIO;
    iocb->dma_buf = spdk_dma_malloc(io->io_len, 4096, NULL);
    if (iocb->dma_buf == NULL) {
        PFS_ASSERT(0 == pfs_put_spdk_io_channel(iocb->ch));
        return -ENOMEM;
    }
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
    rc = spdk_bdev_read(dkdev->dk_desc, iocb->ch, iocb->dma_buf, io->io_bda,
              io->io_len, pfs_spdk_dev_io_done, iocb);
    if (rc == ENOMEM) {
        iocb->bdev_io_wait.bdev = dkdev->dk_bdev;
        iocb->bdev_io_wait.cb_fn = pfs_spdk_dev_io_pread;
        iocb->bdev_io_wait.cb_arg = iocb;
        spdk_bdev_queue_io_wait(dkdev->dk_bdev, iocb->ch,
                                &iocb->bdev_io_wait);
    } else if (rc) {
        PFS_ASSERT(0 == pfs_put_spdk_io_channel(iocb->ch));
        spdk_dma_free(iocb->dma_buf);
        SPDK_ERRLOG("%s error while reading from bdev: %d\n", 
            spdk_strerror(-rc), rc);
        abort();
    }
}

static int
pfs_spdk_dev_io_prep_pwrite(pfs_spdk_dev_t *dkdev, pfs_devio_t *io,
    pfs_spdk_iocb_t *iocb)
{
    int rc;

    PFS_ASSERT(pfs_spdk_dev_dio_aligned(dkdev, io->io_bda));
    PFS_ASSERT(pfs_spdk_dev_dio_aligned(dkdev, io->io_len));

    iocb->ch = pfs_get_spdk_io_channel(dkdev->dk_desc);
    if (iocb->ch == NULL)
	    return -EIO;
    iocb->dma_buf = spdk_dma_malloc(io->io_len, 4096, NULL);
    if (iocb->dma_buf == NULL) {
        PFS_ASSERT(0 == pfs_put_spdk_io_channel(iocb->ch));
        return -ENOMEM;
    }
    rte_memcpy(iocb->dma_buf, io->io_buf, io->io_len);
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
    rc = spdk_bdev_write(dkdev->dk_desc, iocb->ch, iocb->dma_buf, io->io_bda,
              io->io_len, pfs_spdk_dev_io_done, iocb);
    if (rc == ENOMEM) {
        iocb->bdev_io_wait.bdev = dkdev->dk_bdev;
        iocb->bdev_io_wait.cb_fn = pfs_spdk_dev_io_pwrite;
        iocb->bdev_io_wait.cb_arg = iocb;
        spdk_bdev_queue_io_wait(dkdev->dk_bdev, iocb->ch,
                                &iocb->bdev_io_wait);
    } else if (rc) {
        PFS_ASSERT(0 == pfs_put_spdk_io_channel(iocb->ch));
        spdk_dma_free(iocb->dma_buf);
        SPDK_ERRLOG("%s error while writting to bdev: %d\n", 
            spdk_strerror(-rc), rc);
        abort();
    }
}

static int
pfs_spdk_dev_io_prep_trim(pfs_spdk_dev_t *dkdev, pfs_devio_t *io,
    pfs_spdk_iocb_t *iocb)
{
    int rc;

    PFS_ASSERT(pfs_spdk_dev_dio_aligned(dkdev, io->io_bda));
    PFS_ASSERT(pfs_spdk_dev_dio_aligned(dkdev, io->io_len));

    iocb->ch = pfs_get_spdk_io_channel(dkdev->dk_desc);
    if (iocb->ch == NULL)
	    return -EIO;
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
    rc = spdk_bdev_unmap(dkdev->dk_desc, iocb->ch, io->io_bda, io->io_len,
            pfs_spdk_dev_io_done, iocb);                 
     if (rc == ENOMEM) {
        iocb->bdev_io_wait.bdev = dkdev->dk_bdev;
        iocb->bdev_io_wait.cb_fn = pfs_spdk_dev_io_trim;
        iocb->bdev_io_wait.cb_arg = iocb;
        spdk_bdev_queue_io_wait(dkdev->dk_bdev, iocb->ch,
                                &iocb->bdev_io_wait);
    } else if (rc) {
        PFS_ASSERT(0 == pfs_put_spdk_io_channel(iocb->ch));
        SPDK_ERRLOG("%s error while trimming bdev: %d\n", 
            spdk_strerror(-rc), rc);
        abort();
    }
}

static int
pfs_spdk_dev_submit_io(pfs_dev_t *dev, pfs_ioq_t *ioq, pfs_devio_t *io)
{   
    pfs_spdk_dev_t *dkdev = (pfs_spdk_dev_t *)dev;
    pfs_spdk_ioq_t *dkioq = (pfs_spdk_ioq_t *)ioq;
    pfs_spdk_iocb_t *iocb = nullptr;
    int err = 0;

    iocb = (pfs_spdk_iocb_t *)calloc(1, sizeof(pfs_spdk_iocb_t));
    iocb->pfs_io = io;
    iocb->dev = dkdev;
    io->io_private = iocb;
    io->io_error = PFSDEV_IO_DFTERR;
    pfs_spdk_dev_enq_inflight_io(dkioq, io);

    switch (io->io_op) {
    case PFSDEV_REQ_RD:
        err = pfs_spdk_dev_io_prep_pread(dkdev, io, iocb);
        if (err)
            goto fail;
        pfs_spdk_dev_io_pread(iocb);
        break;
    case PFSDEV_REQ_WR:
        err = pfs_spdk_dev_io_prep_pwrite(dkdev, io, iocb);
        if (err)
            goto fail;
        pfs_spdk_dev_io_pwrite(iocb);
        break;
    case PFSDEV_REQ_TRIM:
        err = pfs_spdk_dev_io_prep_trim(dkdev, io, iocb);
        if (err)
            goto fail;
        pfs_spdk_dev_io_trim(iocb);
        break;
    default:
        err = EINVAL;
        pfs_etrace("invalid io task! op: %d, bufp: %p, len: %zu, bda%lu\n",
            io->io_op, io->io_buf, io->io_len, io->io_bda);
        PFS_ASSERT("unsupported io type" == NULL);
    }

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
            pfs_spdk_poll_current_thread();
        } else {
            pfs_spdk_dev_deq_complete_io(dkioq, nio);
            break;
        }
    }
    return nio;
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
};

