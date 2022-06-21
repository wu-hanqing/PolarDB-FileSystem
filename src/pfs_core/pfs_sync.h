#ifndef _PFS_SYNC_H
#define _PFS_SYNC_H

#include <unistd.h>

typedef struct pfs_tid *pfs_thread_id_t;

pfs_thread_id_t pfs_current_id();

#if PFS_USE_BTHREAD

#include <bthread/bthread.h>
#include <bthread/butex.h>
#include <bthread/condition_variable.h>
#include <bthread/rwlock.h>

typedef bthread_t      pfs_thread_t;
typedef bthread_attr_t pfs_thread_attr_t;
typedef bthread_key_t  pfs_key_t;

typedef struct pfs_mutex {
    bthread_mutex_t m;
} pfs_mutex_t;
typedef struct pfs_cond {
    bthread_cond_t cond;
} pfs_cond_t;
typedef struct pfs_rwlock {
    bthread_rwlock_t rw;
} pfs_rwlock_t;
typedef struct pfs_event {
    void *butex; 
} pfs_event_t;

inline pfs_thread_t pfs_thread_self() {
    return bthread_self();
}

inline int pfs_usleep(useconds_t usec)
{
    return bthread_usleep(usec);
}

inline int pfs_thread_create(pfs_thread_t* tid, const pfs_thread_attr_t *attr,
                      void * (*fn)(void*), void* args)
{
    return bthread_start_background(tid, attr, fn, args);
}

inline int pfs_thread_create_urgent(pfs_thread_t* tid, const pfs_thread_attr_t *attr,
                      void * (*fn)(void*), void* args)
{
    return bthread_start_urgent(tid, attr, fn, args);
}

inline void pfs_thread_exit(void *retval)
{
    bthread_exit(retval);
}

inline int pfs_thread_join(pfs_thread_t bt, void** bthread_return)
{
    return bthread_join(bt, bthread_return);
}

inline int pfs_thread_detach(pfs_thread_t bt)
{
    return 0;
}

inline int pfs_mutex_init(pfs_mutex_t *m) {
    return bthread_mutex_init(&m->m, NULL);
}

inline int pfs_mutex_destroy(pfs_mutex_t *m) {
    return bthread_mutex_destroy(&m->m);
}

inline int pfs_mutex_trylock(pfs_mutex_t* m)
{
    return bthread_mutex_trylock(&m->m);
}

inline int pfs_mutex_lock(pfs_mutex_t* m)                          
{
    return bthread_mutex_lock(&m->m);
}

inline int pfs_mutex_unlock(pfs_mutex_t *m)
{
    return bthread_mutex_unlock(&m->m);
}

inline int pfs_cond_init(pfs_cond_t *cond)
{
    return bthread_cond_init(&cond->cond, NULL);
}

inline int pfs_cond_destroy(pfs_cond_t* cond)
{
    return bthread_cond_destroy(&cond->cond);
}

inline int pfs_cond_signal(pfs_cond_t* cond)
{
    return bthread_cond_signal(&cond->cond);
}

inline int pfs_cond_broadcast(pfs_cond_t* cond)
{
    return bthread_cond_broadcast(&cond->cond);
}

inline int pfs_cond_wait(pfs_cond_t* cond, pfs_mutex_t *mutex)
{
    return bthread_cond_wait(&cond->cond, &mutex->m);
}

inline int pfs_cond_timedwait(pfs_cond_t *cond, pfs_mutex_t *mutex,
   const struct timespec* abstime)
{
    return bthread_cond_timedwait(&cond->cond, &mutex->m, abstime);
}

inline int pfs_rwlock_init(pfs_rwlock_t* rwlock)
{
    return bthread_rwlock_init(&rwlock->rw, NULL);
}

inline int pfs_rwlock_destroy(pfs_rwlock_t* rwlock)
{
    return bthread_rwlock_destroy(&rwlock->rw);
}

inline int pfs_rwlock_tryrdlock(pfs_rwlock_t* rwlock)
{
    return bthread_rwlock_tryrdlock(&rwlock->rw);
}

inline int pfs_rwlock_rdlock(pfs_rwlock_t* rwlock)
{
    return bthread_rwlock_rdlock(&rwlock->rw);
}

inline int pfs_rwlock_trywrlock(pfs_rwlock_t* rwlock)
{
    return bthread_rwlock_trywrlock(&rwlock->rw);
}

inline int pfs_rwlock_wrlock(pfs_rwlock_t* rwlock)
{
    return bthread_rwlock_wrlock(&rwlock->rw);
}

inline int pfs_rwlock_unlock(pfs_rwlock_t* rwlock)
{
    return bthread_rwlock_unlock(&rwlock->rw);
}

inline int pfs_key_create(pfs_key_t* key, void (*destructor)(void* data))
{
    return bthread_key_create(key, destructor); 
}

inline int pfs_key_delete(pfs_key_t key)
{
    return bthread_key_delete(key);
}

inline int pfs_setspecific(pfs_key_t key, void* data)
{
    return bthread_setspecific(key, data);
}

inline void* pfs_getspecific(bthread_key_t key)
{
    return bthread_getspecific(key);
}

#else

#include <pthread.h>
#include <semaphore.h>

typedef pthread_t      pfs_thread_t;
typedef pthread_attr_t pfs_thread_attr_t;
typedef pthread_key_t  pfs_key_t;
typedef struct pfs_mutex {
    pthread_mutex_t m;
} pfs_mutex_t;
typedef struct pfs_cond {
    pthread_cond_t cond;
} pfs_cond_t;
typedef struct pfs_rwlock {
    pthread_rwlock_t rw;
} pfs_rwlock_t;
typedef struct pfs_event {
    sem_t sem;
} pfs_event_t;

inline int pfs_usleep(useconds_t usec)
{
    return usleep(usec);
}

inline pfs_thread_t pfs_thread_self() {
    return pthread_self();
}

inline int pfs_mutex_init(pfs_mutex_t *m) {
    return pthread_mutex_init(&m->m, NULL);
}

inline int pfs_mutex_destroy(pfs_mutex_t *m) {
    return pthread_mutex_destroy(&m->m);
}

inline int pfs_mutex_trylock(pfs_mutex_t* m)
{
    return pthread_mutex_trylock(&m->m);
}

inline int pfs_mutex_lock(pfs_mutex_t* m)                          
{
    return pthread_mutex_lock(&m->m);
}

inline int pfs_mutex_unlock(pfs_mutex_t *m)
{
    return pthread_mutex_unlock(&m->m);
}

inline int pfs_cond_init(pfs_cond_t *cond)
{
    return pthread_cond_init(&cond->cond, NULL);
}

inline int pfs_cond_destroy(pfs_cond_t* cond)
{
    return pthread_cond_destroy(&cond->cond);
}

inline int pfs_cond_signal(pfs_cond_t* cond)
{
    return pthread_cond_signal(&cond->cond);
}

inline int pfs_cond_broadcast(pfs_cond_t* cond)
{
    return pthread_cond_broadcast(&cond->cond);
}

inline int pfs_cond_wait(pfs_cond_t* cond, pfs_mutex_t *mutex)
{
    return pthread_cond_wait(&cond->cond, &mutex->m);
}

inline int pfs_cond_timedwait(pfs_cond_t *cond, pfs_mutex_t *mutex,
   const struct timespec* abstime)
{
    return pthread_cond_timedwait(&cond->cond, &mutex->m, abstime);
}

inline int pfs_rwlock_init(pfs_rwlock_t* rwlock)
{
    return pthread_rwlock_init(&rwlock->rw, NULL);
}

inline int pfs_rwlock_destroy(pfs_rwlock_t* rwlock)
{
    return pthread_rwlock_destroy(&rwlock->rw);
}

inline int pfs_rwlock_tryrdlock(pfs_rwlock_t* rwlock)
{
    return pthread_rwlock_tryrdlock(&rwlock->rw);
}

inline int pfs_rwlock_rdlock(pfs_rwlock_t* rwlock)
{
    return pthread_rwlock_rdlock(&rwlock->rw);
}

inline int pfs_rwlock_trywrlock(pfs_rwlock_t* rwlock)
{
    return pthread_rwlock_trywrlock(&rwlock->rw);
}

inline int pfs_rwlock_wrlock(pfs_rwlock_t* rwlock)
{
    return pthread_rwlock_wrlock(&rwlock->rw);
}

inline int pfs_rwlock_unlock(pfs_rwlock_t* rwlock)
{
    return pthread_rwlock_unlock(&rwlock->rw);
}

inline int pfs_thread_create(pfs_thread_t* tid, const pfs_thread_attr_t *attr,
                      void * (*fn)(void*), void* args)
{
    return pthread_create(tid, attr, fn, args);
}

inline int pfs_thread_create_urgent(pfs_thread_t* tid, const pfs_thread_attr_t *attr,
                      void * (*fn)(void*), void* args)
{
    return pthread_create(tid, attr, fn, args);
}

inline void pfs_thread_exit(void *retval)
{
    pthread_exit(retval);
}

inline int pfs_thread_join(pfs_thread_t bt, void** bthread_return)
{
    return pthread_join(bt, bthread_return);
}

inline int pfs_thread_detach(pfs_thread_t bt)
{
    return pthread_detach(bt);
}

inline int pfs_key_create(pfs_key_t* key, void (*destructor)(void* data))
{
    return pthread_key_create(key, destructor); 
}

inline int pfs_key_delete(pfs_key_t key)
{
    return pthread_key_delete(key);
}

inline int pfs_setspecific(pfs_key_t key, void* data)
{
    return pthread_setspecific(key, data);
}

inline void* pfs_getspecific(pfs_key_t key)
{
    return pthread_getspecific(key);
}

#endif // PFS_USE_BTHREAD

void pfs_event_init(pfs_event_t *e);
void pfs_event_destroy(pfs_event_t *e);
void pfs_event_wait(pfs_event_t *e);
void pfs_event_set(pfs_event_t *e);

#endif // _PFS_SYNC_H
