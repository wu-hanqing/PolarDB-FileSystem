#include "pfs_spdk.h"
#include "pfs_trace.h"
#include "pfs_memory.h"

#include <semaphore.h>
#include <memory>
#include <stdlib.h>
#include <string.h>
#include <gflags/gflags.h>
#include <spdk/init.h>
#include <spdk/env.h>
#include <spdk/string.h>
#include <spdk/log.h>
#include <spdk/util.h>

DEFINE_string(spdk_name, "pfsd", "give a name for spdk_env");
DEFINE_string(spdk_core_mask, "", "spdk cpu core mask");
DEFINE_int32(spdk_shm_id, -1, "spdk shared memmory id");
DEFINE_int32(spdk_mem_channel, -1, "spdk memmory channel");
DEFINE_int32(spdk_main_core, -1, "spdk main cpu core id");
DEFINE_int32(spdk_mem_size, -1, "spdk hugetlb memory size");
DEFINE_bool(spdk_no_pci, false, "dont detect PCI");
DEFINE_bool(spdk_hugepage_single_segments, false, "single huge page seg");
DEFINE_bool(spdk_unlink_hugepage, false, "unlink hugepage file");
DEFINE_string(spdk_hugedir, "", "spdk hugedir");
DEFINE_string(spdk_pci_blocked, "", "blocked PCI address");
DEFINE_string(spdk_pci_allowed, "", "allowed PCI address");
DEFINE_string(spdk_iova_mode, "", "iova mode");
DEFINE_uint64(spdk_base_virtaddr, 0x200000000000, "base virtual base");
DEFINE_string(spdk_env_context, "", "env context string");
DEFINE_string(spdk_json_config_file, "", "spdk json config file");
DEFINE_string(spdk_rpc_addr, SPDK_DEFAULT_RPC_ADDR, "spdk rpc address");
DEFINE_string(spdk_log_flags, "", "spdk log flags");
DEFINE_int32(spdk_log_level, SPDK_LOG_INFO, "spdk log level");
DEFINE_int32(spdk_log_print_level, SPDK_LOG_INFO, "spdk log level");

static pthread_mutex_t g_pfs_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_init_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_init_cond;
static bool g_poll_loop = true;
static pthread_t g_init_thread_id;
static int g_spdk_env_initialized;

struct init_param {
    sem_t sem;
    int rc;
};

#define POLLING_TIMEOUT 1000000000ULL
static __thread bool g_pfs_thread = false;
static TAILQ_HEAD(, pfs_spdk_thread) g_gc_threads =
    TAILQ_HEAD_INITIALIZER(g_gc_threads);
static TAILQ_HEAD(, pfs_spdk_thread) g_pfs_threads =
    TAILQ_HEAD_INITIALIZER(g_pfs_threads);

static void pfs_spdk_bdev_close_targets(void *arg);

static void
bdev_event_cb(enum spdk_bdev_event_type type, struct spdk_bdev *bdev,
    void *event_ctx)
{
    SPDK_WARNLOG("Unsupported bdev event: type %d\n", type);
    return;
}

static void init_target(struct pfs_spdk_target *t)
{
    t->desc = nullptr;
    t->channel = nullptr;
    t->ref = 0;
    t->closed = 0;
}

static void fini_thread(struct pfs_spdk_thread *t)
{
    pthread_mutex_destroy(&t->mtx);
}

static void
parse_pci_address(struct spdk_env_opts *opts)
{
    std::string s;
    char *cp, *t;
    struct spdk_pci_addr **pa;

    opts->pci_blocked = NULL;
    opts->pci_allowed = NULL;
    if (!FLAGS_spdk_pci_blocked.empty()) {
        s = FLAGS_spdk_pci_blocked;
        pa = &opts->pci_blocked;
    } else {
        s = FLAGS_spdk_pci_allowed;
        pa = &opts->pci_allowed;
    }
    *pa = NULL;
    if (s.empty())
	return;

    std::unique_ptr<char, decltype(free)*> store(strdup(s.c_str()), free);

    cp = store.get();
    opts->num_pci_addr = 0;
    while ((t = strsep(&cp, " ,"))) {
        struct spdk_pci_addr addr;
        if (spdk_pci_addr_parse(&addr, t)) {
            pfs_etrace("can not parse pci address: %s\n", t);
        } else {
            *pa = (spdk_pci_addr *)realloc(*pa,
                sizeof(spdk_pci_addr) * (1 +  opts->num_pci_addr));
            (*pa)[opts->num_pci_addr++] = addr;
        }
    }
}

static void
set_spdk_opts_from_gflags(struct spdk_env_opts *opts)
{
    if (!FLAGS_spdk_name.empty()) {
        opts->name = FLAGS_spdk_name.c_str();
    }
    if (!FLAGS_spdk_core_mask.empty()) {
        opts->core_mask = FLAGS_spdk_core_mask.c_str();
    }
    opts->mem_channel = FLAGS_spdk_mem_channel;
    opts->main_core = FLAGS_spdk_main_core;
    opts->mem_size = FLAGS_spdk_mem_size;
    opts->no_pci = FLAGS_spdk_no_pci;
    opts->hugepage_single_segments = FLAGS_spdk_hugepage_single_segments;
    if (!FLAGS_spdk_hugedir.empty()) {
        opts->hugedir = FLAGS_spdk_hugedir.c_str();
    }
    if (!FLAGS_spdk_iova_mode.empty()) {
        opts->iova_mode = FLAGS_spdk_iova_mode.c_str();
    }
    
    opts->base_virtaddr = FLAGS_spdk_base_virtaddr;
    parse_pci_address(opts);
}

static void
pfs_spdk_bdev_init_done(int rc, void *cb_arg)
{
    *(bool *)cb_arg = true;
}

static void
pfs_spdk_bdev_init_start(void *arg)
{
    bool *done = (bool *) arg;

    spdk_subsystem_init_from_json_config(
        FLAGS_spdk_json_config_file.c_str(),
        FLAGS_spdk_rpc_addr.c_str(),
        pfs_spdk_bdev_init_done, done, true);
}

static int
pfs_spdk_schedule_thread(struct spdk_thread *spdk_thread)
{
    struct pfs_spdk_thread *thread;

    thread = (struct pfs_spdk_thread *) spdk_thread_get_ctx(spdk_thread);
    memset(thread, 0, sizeof(*thread));
    TAILQ_INIT(&thread->targets);
    pthread_mutex_init(&thread->mtx, NULL);

    if (!g_pfs_thread) {
        /* Do nothing. */
        return 0;
    }

    pthread_mutex_lock(&g_pfs_mtx);
    thread->on_pfs_list = 1;
    TAILQ_INSERT_TAIL(&g_pfs_threads, thread, link);
    pthread_mutex_unlock(&g_pfs_mtx);

    return 0;
}

static int
pfs_spdk_init_thread(struct pfs_spdk_thread **td, bool pfs)
{
    struct pfs_spdk_thread *thread;
    struct spdk_thread *spdk_thread;

    g_pfs_thread = pfs; 
    spdk_thread = spdk_thread_create(pfs? "pfs_thread" : "", NULL);
    g_pfs_thread = false;
    if (!spdk_thread) {
        SPDK_ERRLOG("failed to allocate thread\n");
        return -1;
    }

    thread = (pfs_spdk_thread *)spdk_thread_get_ctx(spdk_thread);
    /* thread is already initialized by pfs_spdk_schedule_thread */
    thread->spdk_thread = spdk_thread;

    spdk_set_thread(spdk_thread);
    *td = thread;
    return 0;
}

static void
pfs_spdk_cleanup_thread(struct pfs_spdk_thread *thread)
{
    pthread_mutex_lock(&g_pfs_mtx);
    if (thread->on_pfs_list) {
        TAILQ_REMOVE(&g_pfs_threads, thread, link);
        thread->on_pfs_list = 0;
    }
    pthread_mutex_unlock(&g_pfs_mtx);
    
    spdk_thread_send_msg(thread->spdk_thread, pfs_spdk_bdev_close_targets,
        thread);

    pthread_mutex_lock(&g_init_mtx);
    TAILQ_INSERT_TAIL(&g_gc_threads, thread, link);
    pthread_mutex_unlock(&g_init_mtx);
}

struct pfs_spdk_thread *pfs_current_spdk_thread(void)
{
    struct spdk_thread *spdk_td = spdk_get_thread();
    struct pfs_spdk_thread *pfs_td;

    if (spdk_td == NULL) {
        if (pfs_spdk_init_thread(&pfs_td, true)) {
            return NULL;
        }
    } else {
        pfs_td = (pfs_spdk_thread *)spdk_thread_get_ctx(spdk_td);
    }
    return pfs_td;
}

struct spdk_io_channel* pfs_get_spdk_io_channel(struct spdk_bdev_desc *desc)
{
    struct pfs_spdk_thread *thread = pfs_current_spdk_thread();
    struct pfs_spdk_target *target;

    pthread_mutex_lock(&thread->mtx);
    TAILQ_FOREACH(target, &thread->targets, link) {
        if (target->desc == desc) {
            target->ref++;
            pthread_mutex_unlock(&thread->mtx);
            return target->channel;
        }
    }

    target = (struct pfs_spdk_target *)
        pfs_mem_malloc(sizeof(*target), M_SPDK_TARGET);
    if (target == NULL) {
        pthread_mutex_unlock(&thread->mtx);
        return NULL;
    }
    init_target(target);

    struct spdk_io_channel* ch = spdk_bdev_get_io_channel(desc);
    if (ch == NULL) {
        pthread_mutex_unlock(&thread->mtx);
        SPDK_ERRLOG("can not get io channel\n");
        pfs_mem_free(target, M_SPDK_TARGET);
        return NULL;
    }

    target->desc = desc;
    target->channel = ch;
    target->ref = 1;
    TAILQ_INSERT_HEAD(&thread->targets, target, link);
    pthread_mutex_unlock(&thread->mtx);
    return ch;
}

int pfs_put_spdk_io_channel(struct spdk_io_channel *ch)
{
    struct pfs_spdk_thread *thread = pfs_current_spdk_thread();
    struct pfs_spdk_target *target, *tmp;
    int rc = -EINVAL;

    pthread_mutex_lock(&thread->mtx);
    TAILQ_FOREACH_SAFE(target, &thread->targets, link, tmp) {
        if (target->channel == ch) {
            target->ref--;
            if (target->ref == 0 && target->closed) {
                spdk_put_io_channel(target->channel);
                TAILQ_REMOVE(&thread->targets, target, link);
                pfs_mem_free(target, M_SPDK_TARGET);
            }
            rc = 0;
            break;
        }
    }
    pthread_mutex_unlock(&thread->mtx);
    return rc;
}

size_t
pfs_spdk_poll_thread(struct pfs_spdk_thread *thread)
{
    return spdk_thread_poll(thread->spdk_thread, 0, 0);
}

static void
pfs_spdk_bdev_close_targets(void *arg)
{
    struct pfs_spdk_thread *thread = (struct pfs_spdk_thread *)arg;
    struct pfs_spdk_target *target, *tmp;

    TAILQ_FOREACH_SAFE(target, &thread->targets, link, tmp) {
        if (target->ref != 0) {
            SPDK_ERRLOG("target ref is not zero\n");
            abort();
        }

        TAILQ_REMOVE(&thread->targets, target, link);
        spdk_put_io_channel(target->channel);
        pfs_mem_free(target, M_SPDK_TARGET);
    }
}

static void
pfs_spdk_calc_timeout(struct pfs_spdk_thread *thread, struct timespec *ts)
{
    uint64_t timeout, now;

    if (spdk_thread_has_active_pollers(thread->spdk_thread)) {
        return;
    }

    timeout = spdk_thread_next_poller_expiration(thread->spdk_thread);
    now = spdk_get_ticks();

    if (timeout == 0) {
        timeout = now + (POLLING_TIMEOUT * spdk_get_ticks_hz()) / SPDK_SEC_TO_NSEC;
    }

    if (timeout > now) {
        timeout = ((timeout - now) * SPDK_SEC_TO_NSEC) / spdk_get_ticks_hz() +
              ts->tv_sec * SPDK_SEC_TO_NSEC + ts->tv_nsec;

        ts->tv_sec  = timeout / SPDK_SEC_TO_NSEC;
        ts->tv_nsec = timeout % SPDK_SEC_TO_NSEC;
    }
}

static void
pfs_spdk_bdev_fini_done(void *cb_arg)
{
    *(bool *)cb_arg = true;
}

static void
pfs_spdk_bdev_fini_start(void *arg)
{
    bool *done = (bool *) arg;

    spdk_subsystem_fini(pfs_spdk_bdev_fini_done, done);
}

static void *thread_poll_loop(void *arg)
{
    struct pfs_spdk_thread *mytd = (struct pfs_spdk_thread *)arg;
    struct pfs_spdk_thread *thread, *tmp;
    struct timespec ts;
    int rc;
    bool done;

    pthread_setname_np(pthread_self(), "pfs_spdk_gc");

    spdk_set_thread(mytd->spdk_thread);
    while (g_poll_loop) {
        pfs_spdk_poll_thread(mytd);

        pthread_mutex_lock(&g_init_mtx);
        if (!TAILQ_EMPTY(&g_gc_threads)) {
            TAILQ_FOREACH_SAFE(thread, &g_gc_threads, link, tmp) {
                if (spdk_thread_is_exited(thread->spdk_thread)) {
                    TAILQ_REMOVE(&g_gc_threads, thread, link);
                    fini_thread(thread);
                    spdk_thread_destroy(thread->spdk_thread);
                } else {
                    pfs_spdk_poll_thread(thread);
                }
            }

            /* If there are exiting threads to poll, don't sleep. */
            pthread_mutex_unlock(&g_init_mtx);
            continue;
        }

        /* Figure out how long to sleep. */
        clock_gettime(CLOCK_REALTIME, &ts);
        pfs_spdk_calc_timeout(mytd, &ts);

        rc = pthread_cond_timedwait(&g_init_cond, &g_init_mtx, &ts);
        pthread_mutex_unlock(&g_init_mtx);

        if (rc != ETIMEDOUT) {
            break;
        }
    }

    pfs_spdk_cleanup_thread(mytd);

    /* Finalize the bdev layer */
    done = false;
    spdk_thread_send_msg(mytd->spdk_thread, pfs_spdk_bdev_fini_start, &done);

    do {
        TAILQ_FOREACH_SAFE(thread, &g_gc_threads, link, tmp) {
            pfs_spdk_poll_thread(thread);
        }
    } while (!done);

    /* Now exit all the threads */
    TAILQ_FOREACH(thread, &g_gc_threads, link) {
        spdk_set_thread(thread->spdk_thread);
        spdk_thread_exit(thread->spdk_thread);
        spdk_set_thread(NULL);
    }

    /* And wait for them to gracefully exit */
    while (!TAILQ_EMPTY(&g_gc_threads)) {
        TAILQ_FOREACH_SAFE(thread, &g_gc_threads, link, tmp) {
            if (spdk_thread_is_exited(thread->spdk_thread)) {
                TAILQ_REMOVE(&g_gc_threads, thread, link);
                fini_thread(thread);
                spdk_thread_destroy(thread->spdk_thread);
            } else {
                spdk_thread_poll(thread->spdk_thread, 0, 0);
            }
        }
    }

    pthread_exit(NULL);
}

static int
pfs_spdk_init_env(void)
{
    struct spdk_env_opts    opts;
    struct pfs_spdk_thread  *mytd, *thread, *tmp;
    struct spdk_thread  *spdk_thread;
    bool                done;
    int                 rc;
    struct timespec     ts;

    memset(&opts, 0, sizeof(opts));
    spdk_env_opts_init(&opts);
    set_spdk_opts_from_gflags(&opts);

    if (spdk_env_init(&opts) < 0) {
        pfs_etrace("Unable to initialize SPDK env\n");
        return -1;
    }

    spdk_unaffinitize_thread();

    if (!FLAGS_spdk_log_flags.empty()) {
        // duplicate string
        std::unique_ptr<char, decltype(free)*>
            store(strdup(FLAGS_spdk_log_flags.c_str()), free);
        char *log_flags = store.get();
        char *tok = strtok(log_flags, ",");
        do {
            rc = spdk_log_set_flag(tok);
            if (rc < 0) {
                pfs_etrace("unknown spdk log flag %s\n", tok);
                return -1;
            }
        } while ((tok = strtok(NULL, ",")) != NULL);
#ifdef DEBUG
        spdk_log_set_print_level(SPDK_LOG_DEBUG);
#endif
    }

    spdk_thread_lib_init(pfs_spdk_schedule_thread,
        sizeof(struct pfs_spdk_thread));

    /* Create an SPDK thread temporarily */
    rc = pfs_spdk_init_thread(&mytd, false);
    if (rc < 0) {
        pfs_etrace("Failed to create initialization thread\n");
        return rc;
    }

    spdk_thread = mytd->spdk_thread;
    /* Initialize the bdev layer */
    done = false;
    spdk_thread_send_msg(spdk_thread, pfs_spdk_bdev_init_start, &done);

    do {
        pfs_spdk_poll_thread(mytd);
    } while (!done);

    /*
     * Continue polling until there are no more events.
     * This handles any final events posted by pollers.
     */
    while (pfs_spdk_poll_thread(mytd) > 0) {}

    spdk_set_thread(NULL);
    rc = pthread_create(&g_init_thread_id, NULL, thread_poll_loop, mytd);
    if (rc) {
        fprintf(stderr, "can not create spdk thread poll thread\n");
        abort();
    }

    return 0;
}

int
pfs_spdk_setup(void)
{
    static pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;

    spdk_log_set_level((spdk_log_level)FLAGS_spdk_log_level);
    spdk_log_set_print_level((spdk_log_level)FLAGS_spdk_log_print_level);

    pthread_mutex_lock(&init_mutex);
    if (!g_spdk_env_initialized) {
        if (pfs_spdk_init_env()) {
            SPDK_ERRLOG("failed to initialize\n");
            pthread_mutex_unlock(&init_mutex);
            return -1;
        }

        g_spdk_env_initialized = true;
	    atexit(pfs_spdk_cleanup);
    }
    pthread_mutex_unlock(&init_mutex);

    pfs_itrace("found devices:\n");
    struct spdk_bdev *bdev;
    for (bdev = spdk_bdev_first(); bdev; bdev = spdk_bdev_next(bdev)) {
         pfs_itrace("\t1: name: %s, size: %ld",
	     spdk_bdev_get_name(bdev),
             spdk_bdev_get_num_blocks(bdev) * spdk_bdev_get_block_size(bdev));
    }
    return 0;
}

void
pfs_spdk_cleanup(void)
{
    struct timespec ts;
    int rc;

    g_poll_loop = false;
    pfs_exit_spdk_thread();

    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 5;
    rc = pthread_timedjoin_np(g_init_thread_id, NULL, &ts);
    if (rc) {
	    printf("can not join spdk polling thread, %s\n", strerror(rc));
    } else {
        spdk_env_fini();
        spdk_log_close();
    }
}

static void
pfs_recycle_thread_io_channels(struct pfs_spdk_thread *thread,
    struct spdk_bdev_desc *desc)
{
    struct pfs_spdk_target *target, *tmp;
    struct spdk_thread *origin = spdk_get_thread();

    spdk_set_thread(thread->spdk_thread);
    pthread_mutex_lock(&thread->mtx);
    TAILQ_FOREACH_SAFE(target, &thread->targets, link, tmp) {
        if (target->desc == desc) {
            if (target->ref != 0) {
                target->closed = 1;
            } else {
                TAILQ_REMOVE(&thread->targets, target, link);
                spdk_put_io_channel(target->channel);
                pfs_mem_free(target, M_SPDK_TARGET);
            }
        }
    }
    pthread_mutex_unlock(&thread->mtx);
    spdk_set_thread(origin);
}

void pfs_spdk_close_all_io_channels(struct spdk_bdev_desc *desc)
{
    struct pfs_spdk_thread *thread;

    pthread_mutex_lock(&g_pfs_mtx);
    TAILQ_FOREACH(thread, &g_pfs_threads, link) {
        assert(thread->on_pfs_list);
        pfs_recycle_thread_io_channels(thread, desc);
    }
    pthread_mutex_unlock(&g_pfs_mtx);
}

void pfs_exit_spdk_thread(void)
{
    struct spdk_thread *spdk_td = spdk_get_thread();
    struct pfs_spdk_thread *pfs_td;

    if (spdk_td == NULL)
        return;
    pfs_td = (pfs_spdk_thread *)spdk_thread_get_ctx(spdk_td);
    spdk_set_thread(NULL);
    pfs_spdk_cleanup_thread(pfs_td);
}

/* functions for mkfs */
void pfs_spdk_conf_set_blocked_pci(const char *s)
{
    FLAGS_spdk_pci_blocked = s;
}

void pfs_spdk_conf_set_allowed_pci(const char *s)
{
    FLAGS_spdk_pci_allowed = s;
}

void pfs_spdk_conf_set_json_config_file(const char *s)
{
    FLAGS_spdk_json_config_file = s;
}

void pfs_spdk_conf_set_name(const char *s)
{
    FLAGS_spdk_name = s;
}

void pfs_spdk_conf_set_env_context(const char *s)
{
    FLAGS_spdk_env_context = s;
}

