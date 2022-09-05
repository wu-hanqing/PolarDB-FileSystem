#include "pfs_iomem.h"
#include "pfs_memory.h"
#include "pfs_impl.h"
#include "pfs_util.h"

#include <unistd.h>
#include <rte_stack.h>

#include "gflags/gflags.h"

DEFINE_int32(pfs_spdk_iobuf_cache, 4000, "pfs spdk iobuf cache");

#define IOMEM "pfs_iobuf"

static struct rte_stack *stack;
static pthread_once_t once_init = PTHREAD_ONCE_INIT;

static void pfs_iomem_init(void)
{
    stack = rte_stack_create(IOMEM, FLAGS_pfs_spdk_iobuf_cache,
                             SOCKET_ID_ANY, RTE_STACK_F_LF);
    if (stack == NULL) {
        fprintf(stderr, "can not create iomem rte_stack\n");
        errno = ENOMEM;
    }
}

static void pfs_iomem_init_once(void)
{
    pthread_once(&once_init, pfs_iomem_init);
}

void *
pfs_iomem_alloc(size_t size)
{
    void *buf;

    pfs_iomem_init_once();

    PFS_ASSERT(PFS_FRAG_SIZE >= size);
    if (rte_stack_pop(stack, &buf, 1)) {
        return buf;
    }
    return pfs_dma_malloc(IOMEM, pfs_getpagesize(), PFS_FRAG_SIZE,
                          SOCKET_ID_ANY);
}

void pfs_iomem_free(void *buf)
{
    pfs_iomem_init_once();

    if (rte_stack_push(stack, &buf, 1))
        return;
    pfs_dma_free(buf);
}

