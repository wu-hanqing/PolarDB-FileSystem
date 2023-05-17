/*
 * Copyright (c) 2017-2021, Alibaba Group Holding Limited
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <rte_memory.h>

#include "pfs_admin.h"
#include "pfs_devio.h"
#include "pfs_devstat.h"
#include "pfs_impl.h"
#include "pfs_mount.h"
#include "pfs_tls.h"
#include "pfs_trace.h"
#include "pfs_stat.h"
#include "pfs_config.h"

#include "pfs_errno_wrapper.h"

#define io_buf io_iov[0].iov_base

#define PFS_MAX_CACHED_DEVIO 128

uint64_t		pfs_devs_epoch;
pfs_dev_t		*pfs_devs[PFS_MAX_NCHD];
static pthread_mutex_t		pfs_devs_mtx;

static __thread SLIST_HEAD(, pfs_devio) tls_free_devio = SLIST_HEAD_INITIALIZER(tls_free_devio);
static int __thread tls_free_devio_num = 0;

/* disable iostat by default */
static int64_t		devstat_enable = PFS_OPT_DISABLE;
PFS_OPTION_REG(devstat_enable, "0", pfs_check_lval_switch);

extern char pfs_trace_pbdname[PFS_MAX_PBDLEN];
extern struct pfs_devops pfs_diskdev_ops;
extern struct pfs_devops pfs_spdk_dev_ops;
static struct pfs_devops *pfs_dev_ops[] = {
//	&pfs_diskdev_ops,
	&pfs_spdk_dev_ops,
	NULL,
};

static pfs_devio_t *pfs_io_alloc(void);
static void pfs_io_destroy(pfs_devio_t *io);

static inline int
pfs_dev_submit_io(pfs_dev_t *dev, pfs_ioq_t *ioq, pfs_devio_t *io)
{
	return dev->d_ops->dop_submit_io(dev, ioq, io);
}

static inline pfs_devio_t *
pfs_dev_wait_io(pfs_dev_t *dev, pfs_ioq_t *ioq, pfs_devio_t *io)
{
	return dev->d_ops->dop_wait_io(dev, ioq, io);
}

static inline pfs_ioq_t *
pfs_dev_create_ioq(pfs_dev_t *dev)
{
	return dev->d_ops->dop_create_ioq(dev);
}

static inline bool
pfs_dev_need_throttle(pfs_dev_t *dev, pfs_ioq_t *ioq)
{
	return dev->d_ops->dop_need_throttle(dev, ioq);
}

static inline int
pfs_dev_open(pfs_dev_t *dev)
{
	return dev->d_ops->dop_open(dev);
}

static inline int
pfs_dev_reopen(pfs_dev_t *dev, int flags)
{
	return dev->d_ops->dop_reopen(dev);
}

static inline int
pfs_dev_close(pfs_dev_t *dev)
{
	return dev->d_ops->dop_close(dev);
}

static inline int
pfs_dev_info(pfs_dev_t *dev, pbdinfo_t *pi)
{
	return dev->d_ops->dop_info(dev, pi);
}

static inline int
pfs_dev_reload(pfs_dev_t *dev)
{
	return dev->d_ops->dop_reload(dev);
}

void __attribute__((constructor))
init_pfs_dev_mtx()
{
	pthread_mutex_init(&pfs_devs_mtx, NULL);
}


/*
 * pfs_devtype_t
 *
 * Get type of device, by inspecting cluster & devname(pbdname)
 * 	1. PBD (cluster=="spdk", devname=="0000:81:00.0n1")
 * 	2. pangu uri (cluster=="river...", devname=="...")
 */
pfs_devtype_t
pfsdev_type(const char *cluster, const char *devname)
{
	int cnt = 0;

	if (strlen(cluster) >= PFS_MAX_CLUSTERLEN ||
	    strlen(devname) >= PFS_MAX_PBDLEN) {
		pfs_etrace("cluster or pbdname is too long\n");
		return PFS_DEV_INVALID;
	}

	// in case 'devname' is pbdpath with leading '/'
	if (devname[0] == '/')
		return PFS_DEV_INVALID;
	if (strcmp(cluster, CL_SPDK) == 0)
		return PFS_DEV_SPDK;
	pfs_etrace("invalid cluster-pbdname combination {%s, %s}\n",
	    cluster, devname);
	return PFS_DEV_INVALID;
}

static int
pfs_dev_alloc_id(pfs_dev_t *dev)
{
	int id;

	pthread_mutex_lock(&pfs_devs_mtx);
	for (id = 0; id < PFS_MAX_NCHD; ++id) {
		if (pfs_devs[id] == NULL) {
			pfs_devs[id] = dev;
			break;
		}
	}
	pthread_mutex_unlock(&pfs_devs_mtx);

	return (id >= PFS_MAX_NCHD) ? -1 : id;
}

static void
pfs_dev_free_id(pfs_dev_t *dev)
{
	int id = dev->d_id;
	PFS_ASSERT(0 <= id && id < PFS_MAX_NCHD);

	pthread_mutex_lock(&pfs_devs_mtx);
	PFS_ASSERT(pfs_devs[id] == dev);
	pfs_devs[id] = NULL;
	pthread_mutex_unlock(&pfs_devs_mtx);
}

static pfs_dev_t *
pfs_dev_create(const char *cluster, const char *devname, int flags)
{
	size_t		devsize, pad_devsize;
	int		devmtag;
	int		err;
	pfs_devtype_t	dtype;
	pfs_dev_t	*dev;
	pfs_devops_t	*dop;

	dtype = pfsdev_type(cluster, devname);
	if (dtype == PFS_DEV_INVALID) {
		pfs_etrace("cluster %s, devname %s: unknown type\n",
		    cluster, devname);
		return NULL;
	}

	for (int i = 0; (dop = pfs_dev_ops[i]) != NULL; i++) {
		if (dop->dop_type == dtype)
			break;
	}
	if (dop == NULL) {
		pfs_etrace("cluster %s, devname %s: cant find device type %d\n",
		    cluster, devname, dtype);
		return NULL;
	}
	devsize = dop->dop_size;
	devmtag = dop->dop_memtag;
	pad_devsize = roundup(devsize, PFS_CACHELINE_SIZE);
	if (pfs_mem_memalign((void **)&dev, PFS_CACHELINE_SIZE,
                             pad_devsize, devmtag)) {
		pfs_etrace("cluster %s, devname %s: no memory\n",
		    cluster, devname);
		return NULL;
	}
	memset(dev, 0, pad_devsize);
	err = strncpy_safe(dev->d_cluster, cluster, PFS_MAX_CLUSTERLEN);
	if (err < 0) {
		pfs_etrace("cluster name too long: %s\n", cluster);
		pfs_mem_free(dev, devmtag);
		return NULL;
	}
	err = strncpy_safe(dev->d_devname, devname, PFS_MAX_PBDLEN);
	if (err < 0) {
		pfs_etrace("device name too long: %s\n", devname);
		pfs_mem_free(dev, devmtag);
		return NULL;
	}
	dev->d_type = dtype;
	dev->d_ops = dop;
	dev->d_flags = flags;
	dev->d_id = pfs_dev_alloc_id(dev);
	if (dev->d_id < 0) {
		pfs_etrace("cluster %s, devname %s: dev id used up\n",
		    cluster, devname);
		pfs_mem_free(dev, devmtag);
		return NULL;
	}
	/* epoch increment only when device open */
	dev->d_epoch = __sync_add_and_fetch(&pfs_devs_epoch, 1);
	dev->d_mem_socket_id = SOCKET_ID_ANY;
	pfs_devstat_init(&dev->d_ds);
	return dev;
}

static void
pfs_dev_destroy(pfs_dev_t *dev)
{
	pfs_devstat_uninit(&dev->d_ds);
	pfs_dev_free_id(dev);
	dev->d_id = -1;
	pfs_mem_free(dev, dev->d_ops->dop_memtag);
}

static void
pfs_io_start(pfs_devio_t *io)
{
	int stat = -1;
	int err;

	err = gettimeofday(&io->io_start_ts, NULL);
	PFS_VERIFY(err == 0);

	pfs_devstat_io_start(&io->io_dev->d_ds, io);

	switch (io->io_op) {
	case PFSDEV_REQ_RD:	stat = STAT_PFS_DEV_READ_BW; break;
	case PFSDEV_REQ_WR: 	stat = STAT_PFS_DEV_WRITE_BW; break;
	case PFSDEV_REQ_TRIM:	stat = -1; break;
	case PFSDEV_REQ_FLUSH:	stat = -1; break;
	default: PFS_ASSERT("io_start bad op" == NULL); break;
	}
	if (stat < 0)
		return;
	PFS_STAT_BANDWIDTH(stat, io->io_len);
}

static void
pfs_io_end(pfs_devio_t *io)
{
	int stat = -1;

	pfs_devstat_io_end(&io->io_dev->d_ds, io);

	switch (io->io_op) {
	case PFSDEV_REQ_RD:	stat = STAT_PFS_DEV_READ_DONE; break;
	case PFSDEV_REQ_WR: 	stat = STAT_PFS_DEV_WRITE_DONE; break;
	case PFSDEV_REQ_TRIM: 	stat = STAT_PFS_DEV_TRIM_DONE; break;
	case PFSDEV_REQ_FLUSH: 	stat = STAT_PFS_DEV_FLUSH_DONE; break;
	default: PFS_ASSERT("io_end bad op" == NULL); break;
	}
	PFS_STAT_LATENCY_VALUE((StatType)stat, &io->io_start_ts);
	(void)stat;	/* suppress compiler error when trace is disabled */

	switch (io->io_op) {
		case PFSDEV_REQ_RD:	stat = MNT_STAT_DEV_READ; break;
		case PFSDEV_REQ_WR: 	stat = MNT_STAT_DEV_WRITE; break;
		case PFSDEV_REQ_TRIM: 	stat = MNT_STAT_DEV_TRIM; break;
		case PFSDEV_REQ_FLUSH: 	stat = MNT_STAT_DEV_FLUSH; break;
		default: PFS_ASSERT("io_end bad op" == NULL); break;
	}

	MNT_STAT_END_VALUE_BANDWIDTH(stat, &io->io_start_ts, io->io_len);
}

static pfs_devio_t *
pfs_io_wait(pfs_devio_t *io, pfs_dev_t *dev)
{
	pfs_devio_t	*nio;
	pfs_ioq_t	*ioq;

	ioq = pfs_tls_get_ioq(dev->d_id, dev->d_epoch);
	PFS_ASSERT(ioq != NULL);
	PFS_ASSERT(io == NULL || io->io_queue == ioq);

	nio = pfs_dev_wait_io(dev, ioq, io);
	PFS_ASSERT(io == NULL || nio == io);
	if (nio == NULL)
		return NULL;
	if (nio->io_error < 0)
		pfs_etrace("io failed! error: %d, pbdname: %s, op: %d, "
		    "buf: %p, len: %lu, bda: %lu, flags: %d\n",
		    nio->io_error, nio->io_dev->d_devname, nio->io_op,
		    nio->io_buf, nio->io_len, nio->io_bda, nio->io_flags);

	pfs_io_end(nio);
	return nio;
}

static int
pfs_io_submit(pfs_devio_t *io)
{
	pfs_dev_t	*dev = io->io_dev;
	int		err = 0;
	bool		waitio = false;
	pfs_ioq_t	*ioq;
	pfs_devio_t	*nio;

	ioq = pfs_tls_get_ioq(dev->d_id, dev->d_epoch);
	if (ioq == NULL) {
		ioq = pfs_dev_create_ioq(dev);
		if (ioq == NULL)
			ERR_RETVAL(ENOMEM);
		ioq->ioq_devid = dev->d_id;
		ioq->ioq_epoch = dev->d_epoch;
		pfs_tls_set_ioq(dev->d_id, ioq);
	}
	io->io_queue = ioq;

	do {
		err = 0;
		if (pfs_dev_need_throttle(dev, ioq) || waitio) {
			MNT_STAT_BEGIN();
			nio = pfs_io_wait(NULL, dev);
			if (waitio)
				MNT_STAT_END(MNT_STAT_DEV_NOBUF);
			else
				MNT_STAT_END(MNT_STAT_DEV_THROTTLE);
			if (nio) {
				PFS_VERIFY(nio != NULL);
				err = nio->io_error;
				pfs_io_destroy(nio);
			}
			waitio = false;
		}
		if (err < 0)
			break;

		err = pfs_dev_submit_io(dev, ioq, io);
		if (err == -ENOBUFS)
			waitio = true;
	} while (waitio);
	if (err < 0)
		return err;

	pfs_io_start(io);
	return 0;
}

static pfs_devio_t *
pfs_io_create(pfs_dev_t *dev, int op, const struct iovec *iov, int iovcnt, size_t len, uint64_t bda,
    int flags)
{
	pfs_devio_t *io;

	io = pfs_io_alloc();
	io->io_dev = dev;
	if (iov) {
		int need_iovcnt = pfs_iovcnt_needed(iov, iovcnt, len);
		if (need_iovcnt == -1) {
			pfs_etrace("iovec is not enough according to given len: %ld\n", len);
			abort();
		}
		if (need_iovcnt > PFSDEV_IOV_MAX) {
			io->io_iov = (struct iovec *)pfs_mem_dalloc(sizeof(struct iovec) * need_iovcnt, M_DEV_IOVEC);
		} else {
			io->io_iov = io->io_iovspace;
		}
		
		int rc = pfs_iov_copy_with_len(iov, need_iovcnt, io->io_iov, len);
		if (rc != need_iovcnt) {
			pfs_etrace("internal error, iovec is not enough");
			abort();
		}
		io->io_iovcnt = need_iovcnt;
	} else {
		io->io_iov = NULL;
		io->io_iovcnt = 0;
	}
	io->io_len = len;
	io->io_bda = bda;
	io->io_op = op;
	io->io_flags = flags;
	io->io_error = PFSDEV_IO_DFTERR;
	io->io_private = NULL;
	io->io_queue = NULL;
	if (devstat_enable == PFS_OPT_ENABLE)
		io->io_flags |= IO_STAT;

	return io;
}

static pfs_devio_t *
pfs_io_alloc(void)
{
	pfs_devio_t *io;

	io = SLIST_FIRST(&tls_free_devio);
	if (io) {
		SLIST_REMOVE_HEAD(&tls_free_devio, io_free);
		tls_free_devio_num--;
		memset(io, 0, sizeof(*io));
		return io;
	}
	io = (pfs_devio_t *)pfs_mem_malloc(sizeof(*io), M_DEV_IO);
	PFS_VERIFY(io != NULL);
	return io;
}

static void
pfs_io_destroy(pfs_devio_t *io)
{
	PFS_ASSERT(io->io_private == NULL);	/* no held private info */
	PFS_ASSERT(io->io_queue != NULL);	/* each io must be submitted */

	if (io->io_iov != io->io_iovspace) {
		pfs_mem_free(io->io_iov, M_DEV_IOVEC);
		io->io_iov = NULL;
	}
	if (tls_free_devio_num < PFS_MAX_CACHED_DEVIO) {
		SLIST_INSERT_HEAD(&tls_free_devio, io, io_free);
		tls_free_devio_num++;
	} else {
		pfs_mem_free(io, M_DEV_IO);
	}
}

int
pfsdev_open(const char *cluster, const char *devname, int flags)
{
	int		err;
	pfs_dev_t	*dev;

	pfs_itrace("open device cluster %s, devname %s, flags %#x\n",
	    cluster, devname, flags);

	dev = pfs_dev_create(cluster, devname, flags);
	if (dev == NULL)
		ERR_RETVAL(EINVAL);

	err = pfs_dev_open(dev);
	if (err < 0) {
		pfs_dev_destroy(dev);
		dev = NULL;
		return err;
	}
	return dev->d_id;
}

int
pfsdev_close(int devi)
{
	int		err;
	pfs_dev_t	*dev;

	pfsdev_flush(devi);

	PFS_ASSERT(0 <= devi && devi < PFS_MAX_NCHD);
	dev = pfs_devs[devi];
	PFS_ASSERT(dev != NULL);

	err = pfs_dev_close(dev);
	if (err < 0) {
		pfs_etrace("dev close ret %d\n", err);
		PFS_VERIFY("dev close failed" == NULL);
	}
	pfs_dev_destroy(dev);
	dev = NULL;
	return 0;
}

int
pfsdev_info(int devi, pbdinfo_t *pi)
{
	pfs_dev_t *dev;

	PFS_ASSERT(0 <= devi && devi < PFS_MAX_NCHD);
	dev = pfs_devs[devi];
	PFS_ASSERT(dev != NULL);

	return pfs_dev_info(dev, pi);
}

int
pfsdev_reload(int devi)
{
	pfs_dev_t	*dev;
	int		err;

	PFS_ASSERT(0 <= devi && devi < PFS_MAX_NCHD);
	dev = pfs_devs[devi];
	PFS_ASSERT(dev != NULL);

	err = pfs_dev_reload(dev);
	if (err < 0)
		pfs_etrace("dev reload failed, ret: %d\n", err);
	return err;
}

static int
pfsdev_do_io(pfs_dev_t *dev, pfs_devio_t *io)
{
	int flags = io->io_flags;
	pfs_devio_t *nio;
	int err;

	err = pfs_io_submit(io);
	if (err)
		pfs_io_destroy(io);
	else if (flags & IO_NOWAIT)
		err = 0;
	else {
		nio = pfs_io_wait(io, dev);
		PFS_ASSERT(nio == io);
		err = io->io_error;
		pfs_io_destroy(io);
	}
	return err;
}

int
pfsdev_trim(int devi, uint64_t bda)
{
	pfs_dev_t *dev;
	pfs_devio_t *io;

	PFS_ASSERT(0 <= devi && devi < PFS_MAX_NCHD);
	dev = pfs_devs[devi];
	PFS_ASSERT(dev != NULL && dev_writable(dev));
	PFS_ASSERT((bda % PFS_BLOCK_SIZE) == 0);

	io = pfs_io_create(dev, PFSDEV_REQ_TRIM, NULL, 0, PFSDEV_TRIMSIZE, bda,
	    IO_WAIT);
	PFS_VERIFY(io != NULL);

	return pfsdev_do_io(dev, io);
}

int
pfsdev_flush(int devi)
{
	pfs_dev_t *dev;
	pfs_devio_t *io;

	PFS_ASSERT(0 <= devi && devi < PFS_MAX_NCHD);
	dev = pfs_devs[devi];
	PFS_ASSERT(dev != NULL);
	if (!dev->d_ops->dop_has_cache(dev) || !dev_writable(dev))
		return 0;
	io = pfs_io_create(dev, PFSDEV_REQ_FLUSH, NULL, 0, 0, 0, IO_WAIT);
	PFS_VERIFY(io != NULL);

	return pfsdev_do_io(dev, io);
}

int
pfsdev_preadv_flags(int devi, const struct iovec *iov, int iovcnt, size_t len, uint64_t bda, int flags)
{
	pfs_dev_t *dev;
	pfs_devio_t *io;
	size_t bsize;

	PFS_ASSERT(0 <= devi && devi < PFS_MAX_NCHD);
	dev = pfs_devs[devi];
        bsize = dev->d_write_unit;
	PFS_ASSERT(dev != NULL);
	PFS_ASSERT((bda & (bsize - 1)) == 0);
	PFS_ASSERT(len > 0 && (len & (bsize-1)) == 0);

	io = pfs_io_create(dev, PFSDEV_REQ_RD, iov, iovcnt, len, bda, flags);
	PFS_VERIFY(io != NULL);

	return pfsdev_do_io(dev, io);
}

int
pfsdev_pread_flags(int devi, void *buf, size_t len, uint64_t bda, int flags)
{
	struct iovec iov;

	iov.iov_base = buf;
	iov.iov_len = len;
	return pfsdev_preadv_flags(devi, &iov, 1, len, bda, flags);
}

int
pfsdev_pwritev_flags(int devi, const struct iovec *iov, int iovcnt,
	size_t len, uint64_t bda, int flags)
{
	pfs_dev_t *dev;
	pfs_devio_t *io;
	size_t bsize;

	PFS_ASSERT(0 <= devi && devi < PFS_MAX_NCHD);
	dev = pfs_devs[devi];
        bsize = dev->d_write_unit;
	PFS_ASSERT(dev != NULL && dev_writable(dev));
	PFS_ASSERT((bda & (bsize - 1)) == 0);
	PFS_ASSERT(len > 0 && (len & (bsize-1)) == 0);

	io = pfs_io_create(dev, PFSDEV_REQ_WR, iov, iovcnt, len, bda, flags);
	PFS_VERIFY(io != NULL);

	return pfsdev_do_io(dev, io);
}

int
pfsdev_pwrite_flags(int devi, void *buf, size_t len, uint64_t bda, int flags)
{
	struct iovec iov;

	iov.iov_base = buf;
	iov.iov_len = len;
	return pfsdev_pwritev_flags(devi, &iov, 1, len, bda, flags);
}

int
pfsdev_wait_io(int devi)
{
	pfs_dev_t	*dev;
	int		err, err1;
	pfs_devio_t	*io;

	PFS_ASSERT(0 <= devi && devi < PFS_MAX_NCHD);
	dev = pfs_devs[devi];
	PFS_ASSERT(dev != NULL);

	err = 0;
	while ((io = pfs_io_wait(NULL, dev)) != NULL) {
		err1 = io->io_error;
		pfs_io_destroy(io);
		ERR_UPDATE(err, err1);
	}
	return err;
}

int
pfsdev_reopen(int devi, const char *cluster, const char *devname, int flags)
{
	pfs_dev_t *dev;

	PFS_ASSERT(0 <= devi && devi < PFS_MAX_NCHD);
	dev = pfs_devs[devi];

	if(cluster)
		PFS_ASSERT(strcmp(dev->d_cluster, cluster) == 0);
	PFS_ASSERT(strcmp(dev->d_devname, devname) == 0);
	dev->d_flags = flags;
	return pfs_dev_reopen(dev, flags);
}

const char *
pfsdev_trace_pbdname(const char *cluster, const char *pbdname)
{
	switch (pfsdev_type(cluster, pbdname)) {
    case PFS_DEV_SPDK:
        return pbdname;
	default:
		return NULL;
	}
}

void
pfsdev_thread_exit(void)
{
	pfs_devio_t *io;

	while ((io = SLIST_FIRST(&tls_free_devio))) {
		SLIST_REMOVE_HEAD(&tls_free_devio, io_free);
		pfs_mem_free(io, M_DEV_IO);
	}
	tls_free_devio_num = 0;
	pfsdev_exit_thread_spdk_drv();
}

int
pfsdev_get_socket_id(int devi)
{
	PFS_ASSERT(0 <= devi && devi < PFS_MAX_NCHD);
	auto dev = pfs_devs[devi];
	return dev->d_mem_socket_id;
}

unsigned
pfsdev_get_cap(int devi)
{
	PFS_ASSERT(0 <= devi && devi < PFS_MAX_NCHD);
	auto dev = pfs_devs[devi];
	return dev->d_cap;
}

unsigned
pfsdev_get_write_unit(int devi)
{
	PFS_ASSERT(0 <= devi && devi < PFS_MAX_NCHD);
	auto dev = pfs_devs[devi];
	return dev->d_write_unit;
}

unsigned
pfsdev_get_buf_align(int devi)
{
	PFS_ASSERT(0 <= devi && devi < PFS_MAX_NCHD);
	auto dev = pfs_devs[devi];
	return dev->d_buf_align;
}
