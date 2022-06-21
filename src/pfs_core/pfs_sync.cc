#include "pfs_tls.h"
#ifdef PFS_USE_BTHREAD
#include <bthread/butex.h>
#else
#include <atomic>
#endif

struct pfs_tid {
};

pfs_thread_id_t pfs_current_id(void)
{
	pfs_tls_t *tls = pfs_current_tls();
	return (struct pfs_tid *)(uintptr_t)tls;
}

#ifdef PFS_USE_BTHREAD
using namespace bthread;
void pfs_event_init(pfs_event_t *e)
{
	e->butex = butex_create();
}

void pfs_event_destroy(pfs_event_t *e)
{
	butex_destroy(e->butex);
}

void pfs_event_wait(pfs_event_t *e)
{
	butex_wait(e->butex, 0, NULL);
	butil::atomic<int> *value = (butil::atomic<int> *)e->butex;
	value->store(0);
}

void pfs_event_set(pfs_event_t *e)
{
	butil::atomic<int> *value = (butil::atomic<int> *)e->butex;
	butil::atomic_thread_fence(butil::memory_order_seq_cst);
	if (value->load())
		return;
	value->store(1);
	butex_wake(e->butex);
}

#else

void pfs_event_init(pfs_event_t *e)
{
	sem_init(&e->sem, 0, 0);
}

void pfs_event_destroy(pfs_event_t *e)
{
	sem_destroy(&e->sem);
}

void pfs_event_wait(pfs_event_t *e)
{
	sem_wait(&e->sem);
}

void pfs_event_set(pfs_event_t *e)
{
	int v;

	std::atomic_thread_fence(std::memory_order_seq_cst);
	sem_getvalue(&e->sem, &v);
	if (v != 0) {
		return;
	}
	sem_post(&e->sem);
}

#endif
