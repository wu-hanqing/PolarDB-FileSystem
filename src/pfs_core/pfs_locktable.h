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
