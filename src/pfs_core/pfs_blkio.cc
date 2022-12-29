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

#include <sys/param.h>

#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_malloc.h>

#include "pfs_blkio.h"
#include "pfs_devio.h"
#include "pfs_mount.h"
#include "pfs_impl.h"
#include "pfs_rangelock.h"                                                      
#include "pfs_locktable.h"
#include "pfs_option.h"
#include "pfs_util.h"
#include "pfs_iomem.h"
#include "pfs_stat.h"

#define PFS_MAXPHYS PBD_UNIT_SIZE

typedef int pfs_blkio_fn_t(
    int iodesc, pfs_bda_t albda, size_t allen, char *albuf,
    pfs_bda_t bda, size_t len, struct iovec *iov, int iovcnt, int ioflags);

/* 
 * 0: block mode (chunk server)
 * 1: file mode (normal pfs)
 */
static int64_t block_io_atomic = 0;

static bool pfs_check_atomic_val(struct pfs_option *, const char *data)
{
	int64_t val;
	if (pfs_strtol(data, &val))
		return false;
	if (val < 0 || val > 1)
		return false;
	return true;
}

PFS_OPTION_REG(block_io_atomic, "0", pfs_check_atomic_val);

static pfs_bda_t
pfs_blkio_align(pfs_mount_t *mnt, int ioflags, int is_write, pfs_bda_t data_bda,
    size_t data_len, size_t *io_len, size_t *op_len)
{
	pfs_bda_t aligned_bda;
	size_t sect_off, frag_off;
	size_t sectsize = pfsdev_get_write_unit(mnt->mnt_ioch_desc);
	size_t fragsize = mnt->mnt_fragsize;

	PFS_ASSERT(sectsize <= mnt->mnt_fragsize);
	sect_off = data_bda & (sectsize - 1);
	frag_off = data_bda & (mnt->mnt_fragsize - 1);
	/* 先处理硬件IO单位限制 */
	if (sect_off != 0) {
		aligned_bda = data_bda - sect_off;
		*op_len = MIN(sectsize - sect_off, data_len);
		*io_len = sectsize;
	} else {
		if (ioflags & (IO_DMABUF | IO_ZERO)) {
			fragsize = PFS_MAXPHYS;
			frag_off = 0;
		}
        	/* 是硬件IO单位的倍数，那么可以根据fragsize 去做IO*/
		aligned_bda = data_bda;
		*op_len = MIN(fragsize - frag_off, data_len);
		*io_len = roundup2(*op_len, sectsize);
		if (is_write && *op_len != *io_len && *io_len > sectsize) {
			/* 减少读然后写的量*/
			*io_len -= sectsize;
			*op_len = *io_len;
		}
	}

	PFS_ASSERT(aligned_bda <= data_bda);
	PFS_ASSERT(aligned_bda < mnt->mnt_disksize);
	PFS_ASSERT(aligned_bda + *io_len <= mnt->mnt_disksize);
	PFS_ASSERT(*io_len <= fragsize);
	PFS_ASSERT((data_bda - aligned_bda) + *op_len <= fragsize);

	return aligned_bda;
}

static int
pfs_blkio_read_segment(int iodesc, pfs_bda_t albda, size_t allen, char *albuf,
    pfs_bda_t bda, size_t len, struct iovec *iov, int iovcnt, int ioflags)
{
	int err;

	if (allen != len) {
		PFS_ASSERT(albuf != NULL);
		PFS_INC_COUNTER(STAT_PFS_UnAligned_R_4K);
		/* align buffer is a dma buffer */
		err = pfsdev_pread_flags(iodesc, albuf, allen, albda, IO_WAIT|IO_DMABUF);
		if (err < 0)
			return err;
		pfs_copy_from_buf_to_iovec(iov, &albuf[bda - albda], len);
		return 0;
	}

	PFS_ASSERT(albda == bda);
	pfs_reset_iovcnt(iov, len, &iovcnt, false);
	err = pfsdev_preadv_flags(iodesc, iov, iovcnt, len, bda, ioflags);
	return err;
}

static int
pfs_blkio_write_segment(int iodesc, pfs_bda_t albda, size_t allen, char *albuf,
    pfs_bda_t bda, size_t len, struct iovec *iov, int iovcnt, int ioflags)
{
	int err;

	if (allen != len) {
		MNT_STAT_BEGIN();
		PFS_ASSERT(albuf != NULL);
		PFS_INC_COUNTER(STAT_PFS_UnAligned_W_4K);
		err = pfsdev_pread_flags(iodesc, albuf, allen, albda, IO_WAIT|IO_DMABUF);
		if (err < 0)
			return err;
		if (ioflags & IO_ZERO)
			memset(&albuf[bda - albda], 0, len);
		else
			pfs_copy_from_iovec_to_buf(&albuf[bda - albda], iov, len);
		err = pfsdev_pwrite_flags(iodesc, albuf, allen, albda, IO_WAIT|IO_DMABUF);
		MNT_STAT_END_BANDWIDTH(MNT_STAT_FILE_WRITE_PAD, len);
		return err;
	}

	PFS_ASSERT(albda == bda);
	pfs_reset_iovcnt(iov, len, &iovcnt, false);
	err = pfsdev_pwritev_flags(iodesc, iov, iovcnt, len, bda, ioflags);
	return err;
}

static int
pfs_blkio_done(int iodesc, int ioflags)
{
	if (!(ioflags & IO_NOWAIT))
		return 0;
	return pfsdev_wait_io(iodesc);
}

static void
pfs_block_lock(pfs_mount_t *mnt, int64_t blkno, off_t woff,
	size_t wlen, struct rangelock **rlp, void *cookie[], int *cc)
{
	const size_t dev_bsize = pfsdev_get_write_unit(mnt->mnt_ioch_desc);
	off_t lock_start = woff, lock_mid_end = 0, lock_end = woff + wlen;
	struct rangelock *rl = NULL;
	pfs_mutex_t *mtx = NULL;

	*cc = 0;
	rl = pfs_locktable_get_rangelock(mnt->mnt_locktable, blkno);
	mtx = &rl->rl_mutex;
	pfs_mutex_lock(mtx);
	if (lock_start & (dev_bsize-1)) {
		lock_start = RTE_ALIGN_FLOOR(lock_start, dev_bsize);
		cookie[*cc] = pfs_rangelock_wlock(rl, lock_start,
			lock_start + dev_bsize, mtx);
		lock_start += dev_bsize;
        	*cc = *cc + 1;
	}

	lock_mid_end = RTE_ALIGN_FLOOR(lock_end, dev_bsize);
	if (lock_start < lock_mid_end) {
		cookie[*cc] = pfs_rangelock_rlock(rl, lock_start,
			lock_mid_end, mtx);
		*cc = *cc + 1;
	}

	lock_mid_end = MAX(lock_start, lock_mid_end);

	if (lock_mid_end < lock_end) {
		lock_end = RTE_ALIGN_CEIL(lock_end, dev_bsize);
		cookie[*cc] = pfs_rangelock_wlock(rl, lock_mid_end,
			 lock_end, mtx);
		*cc = *cc + 1;
	}
	pfs_mutex_unlock(mtx);
	*rlp = rl;
}

static void
pfs_block_unlock(pfs_mount_t *mnt, uint64_t blkno,
	struct rangelock *rl, void **cookie, int cc)
{
	pfs_mutex_t *mtx = NULL;

	mtx = &rl->rl_mutex;
	pfs_mutex_lock(mtx);
	for (int i = 0; i < cc; ++i) {
		pfs_rangelock_unlock(rl, cookie[i], mtx);
	}
	pfs_mutex_unlock(mtx);
	pfs_locktable_put_rangelock(mnt->mnt_locktable, blkno, rl);
}

static ssize_t
pfs_blkio_execute(pfs_mount_t *mnt, struct iovec **iov, int *iovcnt, pfs_blkno_t blkno,
    off_t off, ssize_t len, pfs_blkio_fn_t *iofunc, int flags)
{
	char *albuf = NULL;
	int err, err1, ioflags;
	pfs_bda_t bda, albda;
	size_t allen, iolen, left;
	const int socket = pfsdev_get_socket_id(mnt->mnt_ioch_desc);
	const size_t dev_bsize = pfsdev_get_write_unit(mnt->mnt_ioch_desc);
	const size_t buf_align = pfsdev_get_buf_align(mnt->mnt_ioch_desc);
	int write_zero = !!(flags & PFS_IO_WRITE_ZERO);
	struct rangelock *rl = NULL;
	void		*cookie[3];
	int		cc = 0;
	int		blk_lock = 0;
	int		is_write = 0;

	err = 0;
	ioflags = (len >= 2*PFS_FRAG_SIZE) ? IO_NOWAIT : 0;
	if (flags & PFS_IO_DMA_ON)
		ioflags |= IO_DMABUF;
	if (flags & PFS_IO_WRITE_ZERO)
		ioflags |= IO_ZERO;

	is_write = (pfs_blkio_write_segment == iofunc);
	if (is_write && !(flags & PFS_IO_NO_LOCK)) {
		/* for mode 0, because curve support 512 bytes sector io,
		 * if our write-unit is larger than the 512, we have to use
		 * io range-lock to do read-merge-write
		 */
		if (block_io_atomic == 0)
			blk_lock = (dev_bsize > 512);
		else
			blk_lock = 1;
	}

	left = len;
	if (blk_lock)
		pfs_block_lock(mnt, blkno, off, len, &rl, cookie, &cc);
	while (left > 0) {
		allen = iolen = 0;
		bda = blkno * mnt->mnt_blksize + off;
		albda = pfs_blkio_align(mnt, ioflags, is_write, bda, left, &allen, &iolen);

		if (allen != iolen && albuf == NULL) {
			albuf = (char *)pfs_iomem_alloc(PFS_FRAG_SIZE, socket);
			PFS_VERIFY(albuf != NULL);
		}

		err = (*iofunc)(mnt->mnt_ioch_desc, albda, allen, albuf, bda,
		    iolen, *iov, *iovcnt, ioflags);
		if (err < 0)
			break;

		if (!(ioflags & IO_ZERO) && !(flags & PFS_IO_ZERO_BUF))
			forward_iovec_iter(iov, iovcnt, iolen);

		off += iolen;
		left -= iolen;
	}

	err1 = pfs_blkio_done(mnt->mnt_ioch_desc, ioflags);
	if (blk_lock)
		pfs_block_unlock(mnt, blkno, rl, cookie, cc);

	if (albuf) {
		pfs_iomem_free(albuf);
		albuf = NULL;
	}

	ERR_UPDATE(err, err1);
	if (err < 0) {
		if (err == -ETIMEDOUT)
			ERR_RETVAL(ETIMEDOUT);
		ERR_RETVAL(EIO);
	}

	return len;
}

ssize_t
pfs_blkio_read(pfs_mount_t *mnt, struct iovec **iov, int *iovcnt,
    pfs_blkno_t blkno, off_t off, ssize_t len, int flags)
{
	ssize_t iolen = 0;

	PFS_ASSERT(off + len <= mnt->mnt_blksize);
	iolen = pfs_blkio_execute(mnt, iov, iovcnt, blkno, off, len,
	    pfs_blkio_read_segment, flags);
	return iolen;
}

ssize_t
pfs_blkio_write(pfs_mount_t *mnt, struct iovec **iov, int *iovcnt,
    pfs_blkno_t blkno, off_t off, ssize_t len, int flags)
{
	ssize_t iolen = 0;
	void *zerobuf = NULL;
	const size_t buf_align = pfsdev_get_buf_align(mnt->mnt_ioch_desc);
	const int socket = pfsdev_get_socket_id(mnt->mnt_ioch_desc);
	const int cap = pfsdev_get_cap(mnt->mnt_ioch_desc);
	struct iovec tmpiov = {0, 0}, *tmpiovp;
	int tmpiovcnt;

	PFS_ASSERT(off + len <= mnt->mnt_blksize);
	if (iov == NULL || *iov == NULL) {
		if (cap & DEV_CAP_ZERO)
			flags |= PFS_IO_WRITE_ZERO;
		else if (!(flags & PFS_IO_WRITE_ZERO)) {
			zerobuf = pfs_iomem_alloc(PFS_FRAG_SIZE, socket);
			memset(zerobuf, 0, PFS_FRAG_SIZE);
			PFS_VERIFY(zerobuf != NULL);
			tmpiov.iov_base = zerobuf;
			tmpiov.iov_len = PFS_FRAG_SIZE;
			flags |= PFS_IO_DMA_ON | PFS_IO_ZERO_BUF;
		}
		tmpiovp = &tmpiov;
		iov = &tmpiovp;
		tmpiovcnt = 1;
		iovcnt = &tmpiovcnt;
	}

	iolen = pfs_blkio_execute(mnt, iov, iovcnt, blkno, off, len,
	    pfs_blkio_write_segment, flags);

	if (zerobuf) {
		pfs_iomem_free(zerobuf);
		zerobuf = NULL;
	}
	return iolen;
}
