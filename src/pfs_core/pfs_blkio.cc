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

#include "pfs_errno_wrapper.h"

typedef int pfs_blkio_fn_t(
    int iodesc, pfs_bda_t albda, size_t allen, char *albuf,
    pfs_bda_t bda, size_t len, const struct iovec *iov, int iovcnt, int ioflags);

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
	pfs_bda_t aligned_bda = -1L;
	size_t sect_off = 0;
	size_t sectsize = pfsdev_get_write_unit(mnt->mnt_ioch_desc);
	size_t fragsize = mnt->mnt_fragsize;

	PFS_ASSERT(sectsize <= mnt->mnt_fragsize);
	sect_off = data_bda & (sectsize - 1);
	/* 先处理硬件IO位置对齐限制 */
	if (sect_off != 0) {
		aligned_bda = data_bda - sect_off;
		*op_len = MIN(sectsize - sect_off, data_len);
		*io_len = sectsize;
	} else {
		/* data_bda是硬件IO单位的倍数, 我们可以直接从这个data_bda位置
		 * 开始IO
		 */
		aligned_bda = data_bda;
		*op_len = MIN(fragsize, data_len);
		*io_len = roundup2(*op_len, sectsize);
		if (is_write && *op_len != *io_len && *io_len > sectsize) {
			/* 如果要补齐读，不如做一次完整的部分写，然后剩余部分
			 * 再读 & 写合并
			 */
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
    pfs_bda_t bda, size_t len, const struct iovec *iov, int iovcnt, int ioflags)
{
	int err = 0;

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
	err = pfsdev_preadv_flags(iodesc, iov, iovcnt, len, bda, ioflags);
	return err;
}

static int
pfs_blkio_write_segment(int iodesc, pfs_bda_t albda, size_t allen, char *albuf,
    pfs_bda_t bda, size_t len, const struct iovec *iov, int iovcnt, int ioflags)
{
	int err = 0;

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
	const int caps = pfsdev_get_cap(mnt->mnt_ioch_desc);
	char *albuf = NULL, *zero_buf = NULL;
	int err = 0, err1 = 0, ioflags = 0;
	pfs_bda_t bda = -1L, albda = -1L;
	size_t allen = 0, iolen = 0, left = 0;
	const int socket = pfsdev_get_socket_id(mnt->mnt_ioch_desc);
	const size_t dev_bsize = pfsdev_get_write_unit(mnt->mnt_ioch_desc);
	struct rangelock *rl = NULL;
	void		*cookie[3] = {NULL, NULL, NULL};
	int		cc = 0;
	int		blk_lock = 0;
	const int       is_write = (pfs_blkio_write_segment == iofunc);
	struct iovec    zero_iov = {0, 0};

	err = 0;
	ioflags = (len >= 2*PFS_FRAG_SIZE) ? IO_NOWAIT : 0;
	if (flags & PFS_IO_DMA_ON)
		ioflags |= IO_DMABUF;
	if (flags & PFS_IO_WRITE_ZERO) {
		/*
		 * 对于写零请求，如果设备支持写零，则使用设备能力，否则申请一个
		 * zero buffer
		 */
		if (caps & DEV_CAP_ZERO)
			ioflags |= IO_ZERO;
		else {
			zero_buf = (char *)pfs_iomem_alloc(PFS_FRAG_SIZE, socket);
			PFS_VERIFY(zero_buf != NULL);
			memset(zero_buf, 0, PFS_FRAG_SIZE);
			zero_iov.iov_base = zero_buf;
			zero_iov.iov_len = PFS_FRAG_SIZE;
			ioflags |= IO_DMABUF;
		}
	} else if (iov == NULL) {
		pfs_etrace("iov is NULL");
		abort();
	}
	if (is_write && !(flags & PFS_IO_NO_LOCK)) {
		/* for mode 0, because curve supports 512 bytes sector io,
		 * if hardware sector is larger than the 512, we have to use
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

		struct iovec *tmp_iov = NULL;
		int tmp_iov_cnt = 0;
		if (!(flags & PFS_IO_WRITE_ZERO)) {
			tmp_iov = *iov;
			tmp_iov_cnt = *iovcnt;
		} else {
			if (!(ioflags & IO_ZERO)) {
				tmp_iov = &zero_iov;
				tmp_iov_cnt = 1;
			}
		}
		err = (*iofunc)(mnt->mnt_ioch_desc, albda, allen, albuf, bda,
		    iolen, tmp_iov, tmp_iov_cnt, ioflags);
		if (err < 0)
			break;

		if (!(flags & PFS_IO_WRITE_ZERO))
			forward_iovec_iter(iov, iovcnt, iolen);

		off += iolen;
		left -= iolen;
	}

	err1 = pfs_blkio_done(mnt->mnt_ioch_desc, ioflags);
	if (blk_lock)
		pfs_block_unlock(mnt, blkno, rl, cookie, cc);

	if (albuf)
		pfs_iomem_free(albuf);
	if (zero_buf)
		pfs_iomem_free(zero_buf);

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
	PFS_ASSERT(off + len <= mnt->mnt_blksize);
	PFS_ASSERT(iov != NULL);
	return pfs_blkio_execute(mnt, iov, iovcnt, blkno, off, len,
	    pfs_blkio_read_segment, flags);
}

ssize_t
pfs_blkio_write(pfs_mount_t *mnt, struct iovec **iov, int *iovcnt,
    pfs_blkno_t blkno, off_t off, ssize_t len, int flags)
{
	PFS_ASSERT(off + len <= mnt->mnt_blksize);
	PFS_ASSERT(iov != NULL || (flags & PFS_IO_WRITE_ZERO));
	return pfs_blkio_execute(mnt, iov, iovcnt, blkno, off, len,
	    pfs_blkio_write_segment, flags);
}
