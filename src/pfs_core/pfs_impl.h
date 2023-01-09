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

#ifndef	_PFS_IMPL_H_
#define	_PFS_IMPL_H_

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pfs_def.h"
#include "pfs_trace.h"
#include "pfs_memory.h"
#include "pfs_util.h"
#include "pfs_sync.h"

/*
 * Macros for PBD information.
 * Note that IO in sector size is atomic.
 */
#define	PBD_CHUNK_SIZE		(10ULL << 30)
#define	PBD_UNIT_SIZE		(4U << 20)
#define	PBD_SECTOR_SIZE		4096U

#define	PFS_BLOCK_SIZE		PBD_UNIT_SIZE
#define	PFS_FRAG_SIZE		(16U << 10)
#define	PFS_OBJDATA_SIZE	(128 - 40)

#define	PFS_NBT_PERCHUNK	((uint32_t)(PBD_CHUNK_SIZE / PFS_BLOCK_SIZE))
#define	PFS_NIN_PERCHUNK	2048	/* # inode per chunk */
#define	PFS_NDE_PERCHUNK	PFS_NIN_PERCHUNK

#define	PFS_MAX_NCHD		16	/* max # io device descriptors */
#define	PFS_MAX_NMOUNT		PFS_MAX_NCHD

//#define	PFS_MAX_COMPNTLEN	(64 - 3*4) /* max file name component length */
#define	PFS_MAX_CLUSTERLEN	(512 - PFS_MAX_PBDLEN) /* 512 is hard-coded in pangu uri */
#define	PFS_MAX_PBDLEN		64	/* max pbdname length, include '\0' */
#define	PFS_MAX_NAMELEN		256	/* max file name length, include '\0' */
#define	PFS_MAX_NAMELEN_OLD	64
#define	PFS_MAX_PATHLEN		4096	/* max pbdpath length, include '\0' */

#define	PFS_CHUNK_MAGIC		0x5046534348ULL	/* PFSCK */
#define	PFS_MAX_VERSION		64

#define	PFS_JOURNAL_FILE	".pfs-journal"
#define	PFS_PAXOS_FILE		".pfs-paxos"

#define PFS_CTIME_SYNC		10	/* file's new ctime is fresh than this,
					   then sysnc inode*/
#define NSEC_PER_USEC		1000L
#define USEC_PER_SEC		1000000L
#define NSEC_PER_SEC		1000000000L

#define PFS_IO_DMA_OFF		0x0
#define PFS_IO_DMA_ON		0x1
#define PFS_IO_WRITE_ZERO	0x2
#define PFS_IO_NO_LOCK		0x4
#define PFS_IO_ZERO_BUF		0x8

/*
 * A block is of unit size, 4M. A fragment is of size 16K.
 * Fragments are to make IO easy; A 4M block is too large for IO.
 */
typedef int64_t			pfs_lsn_t;	/* log sequence number */
typedef int64_t			pfs_txid_t;	/* transaction id */

/* blkid is counted within a file, starting with 0.  */
typedef int64_t			pfs_blkid_t;

/* blkno is counted within a PBD, starting from 0.  */
typedef int64_t			pfs_blkno_t;	/* block number */
#define	BLKNO_HOLE		((pfs_blkno_t)0LL)
#define	BLKNO_INVALID		((pfs_blkno_t)-1LL)
#define	BLKNO_NEW		((pfs_blkno_t)-2LL)

typedef	uint64_t		pfs_bda_t;	/* block device addr */

/* ino is the number for the inode meta object */
typedef int64_t			pfs_ino_t;	/* inode number */

#define	DUMP_FIELD(format, lvl, obj, field) 			\
	printf("%*s%-10s " format "\n", 2*(lvl), " ", #field, (obj)->field)

#define	DUMP_VALUE(format, lvl, key, val) 			\
	printf("%*s%-10s " format "\n", 2*(lvl), " ", #key, val)

/*
 * ATTENTION NOTE:
 *
 * The macros below are used for generatating original error code.
 * 'original' here means the point is source where an error occurs.
 *
 * If it is not the original error point, just use ordinary return
 * or goto.
 */
#define	ERR_MSG(errcode)	do {				\
	pfs_etrace("%s:%d failed, error %d: %s\n",		\
	    __func__, __LINE__, (int)errcode, 			\
	    errcode ? strerror(errcode) : "pfs internal");	\
} while(0)

#define ERR_GOTO(errcode, label) do {				\
	ERR_MSG(errcode);					\
	err = -errcode;						\
	goto label;						\
} while(0)

#define	ERR_RETVAL(errcode) 	do {				\
	ERR_MSG(errcode);					\
	return -errcode;					\
} while(0)

#define ERR_UPDATE(a, b)  do {		\
	if (a >= 0 && b < 0)			\
		a = b;						\
} while (0)

#define PFS_CACHELINE_SIZE 64

void	pfs_abort(const char *action, const char *cond, const char *func,
	    int line);

#if 0
#define	BACKTRACE_STDERR do {					\
	void *__buf[SYM_SIZE];					\
	int __nsym = backtrace(__buf, SYM_SIZE);		\
	backtrace_symbols_fd(__buf, __nsym, STDERR_FILENO);	\
} while(0)
#endif

#define	PFS_ASSERT(cond)	do {				\
	if (unlikely(!(cond)))					\
		pfs_abort("assert", #cond, __func__, __LINE__);	\
} while(0)

#define	PFS_VERIFY(cond)	do {				\
	if (unlikely(!(cond)))					\
		pfs_abort("verify", #cond, __func__, __LINE__);	\
} while(0)

#define	PAXOS_FILE_MONO		1
#define	JOURNAL_FILE_MONO	2

#ifndef offsetof
#define offsetof(TYPE, MEMBER)					\
	((size_t) &((TYPE *)0)->MEMBER)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({			\
	const __typeof__(((type *)0)->member) * __mptr = (ptr);	\
	(type *)((char *)__mptr - offsetof(type, member)); })
#endif

static inline void
mutex_init(pfs_mutex_t *mtx)
{
	int err;
/*
	pthread_mutexattr_t attr;

	err = pthread_mutexattr_init(&attr);
	err |= pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
	err |= pthread_mutex_init(mtx, &attr);
	err |= pthread_mutexattr_destroy(&attr);
*/
	err = pfs_mutex_init(mtx);
	PFS_VERIFY(err == 0);
}

static inline void
mutex_destroy(pfs_mutex_t *mtx)
{
	PFS_ASSERT(pfs_mutex_destroy(mtx) == 0);
}

static inline void
mutex_lock(pfs_mutex_t *mtx)
{
	PFS_ASSERT(pfs_mutex_lock(mtx) == 0);
}

static inline void
mutex_unlock(pfs_mutex_t *mtx)
{
	PFS_ASSERT(pfs_mutex_unlock(mtx) == 0);
}

static inline void
cond_init(pfs_cond_t *cnd, const void *attr)
{
	PFS_ASSERT(pfs_cond_init(cnd) == 0);
}

static inline void
cond_destroy(pfs_cond_t *cnd)
{
	PFS_ASSERT(pfs_cond_destroy(cnd) == 0);
}

static inline void
cond_wait(pfs_cond_t *cnd, pfs_mutex_t *mtx)
{
	PFS_ASSERT(pfs_cond_wait(cnd, mtx) == 0);
}

static inline int
cond_timedwait(pfs_cond_t *cnd, pfs_mutex_t *mtx, const struct timespec *abstime)
{
	int err;
	err = pfs_cond_timedwait(cnd, mtx, abstime);
	PFS_ASSERT(err == 0 || err == ETIMEDOUT);
	return err;
}

static inline void
cond_signal(pfs_cond_t *cnd)
{
	PFS_ASSERT(pfs_cond_signal(cnd) == 0);
}

static inline void
cond_broadcast(pfs_cond_t *cnd)
{
	PFS_ASSERT(pfs_cond_broadcast(cnd) == 0);
}

static inline void
rwlock_init(pfs_rwlock_t *rwlock, const void *attr) 
{
	PFS_ASSERT(pfs_rwlock_init(rwlock) == 0);
}

static inline void
rwlock_destroy(pfs_rwlock_t *rwlock)
{
	PFS_ASSERT(pfs_rwlock_destroy(rwlock) == 0);
}

static inline void
rwlock_wrlock(pfs_rwlock_t *rwlock)
{
	PFS_ASSERT(pfs_rwlock_wrlock(rwlock) == 0);
}

static inline void
rwlock_rdlock(pfs_rwlock_t *rwlock)
{
	PFS_ASSERT(pfs_rwlock_rdlock(rwlock) == 0);
}

static inline int
rwlock_tryrdlock(pfs_rwlock_t *rwlock)
{
	return pfs_rwlock_tryrdlock(rwlock);
}

static inline void
rwlock_unlock(pfs_rwlock_t *rwlock)
{
	PFS_ASSERT(pfs_rwlock_unlock(rwlock) == 0);
}

/*
 * In a binary tree, the first element of tree node
 * struct is the pointer of tkey_t. So a tree node
 * is also the pointer of tkey_t.
 */
typedef void		tkey_t;
typedef void		tnode_t;
#define	TNODE_KEY(nodep) (*(tkey_t **)(nodep))

/*
 * PFS internal APIs
 */
typedef struct fmap_entry {
	/* input */
	off_t	f_off;

	/* output */
	int64_t	f_ckid;
	int64_t	f_blkno;
	int64_t	f_btno;
	int32_t	f_bthoff;
} fmap_entry_t;

int	pfs_fmap(int fd, fmap_entry_t *fmapv, int count);
int	pfs_du(const char *path, int all, int depth, pfs_printer_t *printer);

#endif	/* _PFS_IMPL_H_ */
