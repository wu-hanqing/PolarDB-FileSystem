/* vim: set ts=4 sw=4 expandtab: */

/*
 *  Copyright (c) 2020 NetEase Inc.
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

/**
 * Project : curve
 * Date : 2022/06/07
 * Author: XuYifeng
 */

#include "pfs_spdk.h"
#include "pfs_trace.h"
#include "pfs_memory.h"

#include <ctype.h>
#include <semaphore.h>
#include <stdlib.h>
#include <string.h>

#include <memory>
#include <stack>
#include <vector>

#include <gflags/gflags.h>

#include <rte_config.h>
#include <rte_memory.h>

#include <spdk/init.h>
#include <spdk/env.h>
#include <spdk/string.h>
#include <spdk/log.h>
#include <spdk/util.h>
#include <spdk/json.h>

#define THREAD_POLL "thread_poll"

DEFINE_string(spdk_name, "", "give a name for spdk_env");
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
DEFINE_string(spdk_iova_mode, "va", "iova mode");
DEFINE_uint64(spdk_base_virtaddr, 0, "base virtual base");
DEFINE_string(spdk_env_context, "", "env context string");
DEFINE_string(spdk_json_config_file, "", "spdk json config file");
DEFINE_string(spdk_rpc_addr, SPDK_DEFAULT_RPC_ADDR, "spdk rpc address");
//DEFINE_string(spdk_log_flags, "bdev,thread,nvme", "spdk log flags");
DEFINE_string(spdk_log_flags, "", "spdk log flags");
DEFINE_int32(spdk_log_level, SPDK_LOG_INFO, "spdk log level");
DEFINE_int32(spdk_log_print_level, SPDK_LOG_INFO, "spdk log level");
DEFINE_string(spdk_nvme_controller, "", "simply configured nvme controller");
DEFINE_int32(spdk_delete_temp_json_file, 1, "delete temp json file");

#define RECYCLE_TIMEOUT 5

static std::string g_spdk_temp_config_file;
static pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;
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
static __thread bool g_pfs_internal = false;
static int g_poll_exit_result = 0;
static TAILQ_HEAD(, pfs_spdk_thread) g_gc_threads =
    TAILQ_HEAD_INITIALIZER(g_gc_threads);
static TAILQ_HEAD(, pfs_spdk_thread) g_pfs_threads =
    TAILQ_HEAD_INITIALIZER(g_pfs_threads);

static void pfs_spdk_bdev_close_targets(void *arg);

static void
bdev_event_cb(enum spdk_bdev_event_type type, struct spdk_bdev *bdev,
    void *event_ctx)
{
    pfs_etrace("Unsupported bdev event: type %d\n", type);
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
    opts->shm_id = FLAGS_spdk_shm_id;
    opts->mem_channel = FLAGS_spdk_mem_channel;
    opts->main_core = FLAGS_spdk_main_core;
    opts->mem_size = FLAGS_spdk_mem_size;
    opts->no_pci = FLAGS_spdk_no_pci;
    opts->hugepage_single_segments = FLAGS_spdk_hugepage_single_segments;
    opts->unlink_hugepage = FLAGS_spdk_unlink_hugepage;
    opts->num_pci_addr = 0;
    if (!FLAGS_spdk_hugedir.empty()) {
        opts->hugedir = FLAGS_spdk_hugedir.c_str();
    }
    parse_pci_address(opts);
    if (!FLAGS_spdk_iova_mode.empty()) {
        opts->iova_mode = FLAGS_spdk_iova_mode.c_str();
    }
    if (FLAGS_spdk_base_virtaddr)
        opts->base_virtaddr = FLAGS_spdk_base_virtaddr;
    if (!FLAGS_spdk_env_context.empty()) {
        opts->env_context = (char *)FLAGS_spdk_env_context.c_str();
    }
}

static void
pfs_spdk_bdev_init_done(int rc, void *cb_arg)
{
    *(bool *)cb_arg = true;
    if (FLAGS_spdk_delete_temp_json_file) {
        unlink(g_spdk_temp_config_file.c_str());
    }
}

/*
 * Generate json config file base on FLAGS_spdk_nvme_controller
 *
 * Return:
 *    failure:   -1
 *    nothing:   0
 *    generated: 1
 */
static int
pfs_generate_json_file(void)
{
    char temp[128];
    int fd;

    if (FLAGS_spdk_nvme_controller.empty())
        return 0;

    strcpy(temp, "/tmp/pfs_spdk_json_config_XXXXXX");
    fd = mkstemp(temp);
    if (fd == -1) {
        pfs_etrace("can not create temp file");
        return -1;
    }

    const char* s1 = R"foo({
    "subsystems":
    [
        {
            "subsystem": "bdev",
            "config":
            [
                {
                    "method": "bdev_nvme_attach_controller",
                    "params":
                    {
                        "trtype": "PCIe",
                        "name":"replace1",
                        "traddr":"replace2"
                    }
                }
            ]
        }
    ]
})foo";

    std::string s = s1;
    auto pos = s.find("replace1");
    if (std::string::npos == pos) {
        pfs_fatal("cannot find substr replace1");
        close(fd);
        return -1;
    }
    s.replace(pos, 8, FLAGS_spdk_nvme_controller);
    pos = s.find("replace2");
    if (std::string::npos == pos) {
        pfs_fatal("cannot find substr replace2");
        close(fd);
        return -1;
    }
    s.replace(pos, 8, FLAGS_spdk_nvme_controller);
    int rc = write(fd, s.data(), s.length()); 
    if (rc == -1)
        pfs_etrace("cannot write file %s, %s", temp, strerror(errno));
    close(fd);
    pfs_itrace("generated json config file: %s", temp);
    if (rc == -1) {
        return -1;
    }
    g_spdk_temp_config_file = temp; 
    return 1;
}

static void
pfs_spdk_bdev_init_start(void *arg)
{
    bool *done = (bool *) arg;
    std::string json_file;

    json_file = g_spdk_temp_config_file;
    if (json_file.empty()) {
        if (FLAGS_spdk_json_config_file.empty())
            pfs_etrace("json config file is not set!");
        else
            json_file = FLAGS_spdk_json_config_file;
        pfs_itrace("json config file: %s", json_file.c_str());
    }

    if (FLAGS_spdk_rpc_addr.empty())
        pfs_etrace("spdk rpc address is not set!");
    else
        pfs_itrace("spdk rpc address:%s", FLAGS_spdk_rpc_addr.c_str());

    spdk_subsystem_init_from_json_config(
        json_file.c_str(),
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

    if (g_pfs_internal)
        return 0;
 
    pthread_mutex_lock(&g_pfs_mtx);
    thread->on_pfs_list = 1;
    TAILQ_INSERT_TAIL(&g_pfs_threads, thread, link);
    pthread_mutex_unlock(&g_pfs_mtx);

    return 0;
}

static int
pfs_spdk_init_thread(struct pfs_spdk_thread **td, const char *name, bool internal)
{
    struct pfs_spdk_thread *thread;
    struct spdk_thread *spdk_thread;

    g_pfs_thread = true;
    g_pfs_internal = internal;
    spdk_thread = spdk_thread_create(name, NULL);
    g_pfs_thread = false;
    g_pfs_internal = false;
    if (!spdk_thread) {
        pfs_etrace("failed to allocate thread\n");
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

    spdk_thread_exit(thread->spdk_thread);
    spdk_thread_send_msg(thread->spdk_thread, pfs_spdk_bdev_close_targets,
        thread);

    pthread_mutex_lock(&g_init_mtx);
    TAILQ_INSERT_TAIL(&g_gc_threads, thread, link);
    pthread_mutex_unlock(&g_init_mtx);
    spdk_set_thread(NULL);
}

struct pfs_spdk_thread *pfs_create_spdk_thread(const char *name)
{
    struct pfs_spdk_thread *pfs_td;

    if (pfs_spdk_init_thread(&pfs_td, name, false))
         return NULL;
    return pfs_td;
}

struct pfs_spdk_thread *pfs_current_spdk_thread(void)
{
    struct spdk_thread *spdk_td = spdk_get_thread();
    struct pfs_spdk_thread *pfs_td;

    if (spdk_td == NULL) {
        return NULL;
    } else {
        pfs_td = (pfs_spdk_thread *)spdk_thread_get_ctx(spdk_td);
    }
    return pfs_td;
}

void pfs_spdk_set_current_thread(struct pfs_spdk_thread *thread)
{
    spdk_set_thread(thread->spdk_thread);
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
        pfs_etrace("can not get io channel\n");
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
            pfs_etrace("target ref is not zero, should put io channel before thread exiting\n");
        }

        pfs_itrace("put io channel %p", target->channel);
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
    pfs_itrace("bdev subsystem shutdown");
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

    pthread_setname_np(pthread_self(), "pfs_spdk_" THREAD_POLL);

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

    struct timeval start, now, end, interval;
    int timeouted = 0;

    interval.tv_sec = 0;//  RECYCLE_TIMEOUT;
    interval.tv_usec = 1000;
    gettimeofday(&start, NULL);
    timeradd(&start, &interval, &end);

    /* Finalize the bdev layer */
    done = false;
    spdk_thread_send_msg(mytd->spdk_thread, pfs_spdk_bdev_fini_start, &done);
    pfs_spdk_cleanup_thread(mytd);

    do {
        TAILQ_FOREACH_SAFE(thread, &g_gc_threads, link, tmp) {
            spdk_set_thread(thread->spdk_thread);
            spdk_thread_poll(thread->spdk_thread, 0, 0);
            spdk_set_thread(NULL);
        }
        gettimeofday(&now, NULL);
        if (timercmp(&now, &end, >=)) {
            pfs_etrace("waiting for spdk bdev shutdown timeout\n");
            g_poll_exit_result = ETIMEDOUT;
            goto out;
        }
    } while (!done);

    pfs_itrace("spdk bdev subsystem is shutdown now");

    /* Now exit all the threads */
    TAILQ_FOREACH(thread, &g_gc_threads, link) {
        spdk_set_thread(thread->spdk_thread);
        spdk_thread_exit(thread->spdk_thread);
        spdk_set_thread(NULL);
    }

    /* And wait for them to gracefully exit */
    while (!TAILQ_EMPTY(&g_gc_threads)) {
        TAILQ_FOREACH_SAFE(thread, &g_gc_threads, link, tmp) {
            spdk_set_thread(thread->spdk_thread);
            if (spdk_thread_is_exited(thread->spdk_thread)) {
                TAILQ_REMOVE(&g_gc_threads, thread, link);
                fini_thread(thread);
                spdk_thread_destroy(thread->spdk_thread);
            } else {
                spdk_thread_poll(thread->spdk_thread, 0, 0);
            }
            spdk_set_thread(NULL);
        }
        gettimeofday(&now, NULL);
        if (timercmp(&now, &end, >=)) {
            pfs_etrace("recycle spdk thread timeout\n");
            break;
        }
    }

out:
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

    if (pfs_generate_json_file() < 0) {
        return -1;
    }

    memset(&opts, 0, sizeof(opts));
    spdk_env_opts_init(&opts);
    set_spdk_opts_from_gflags(&opts);

    if (spdk_env_init(&opts) < 0) {
        pfs_etrace("Unable to initialize SPDK env\n");
        return -1;
    }

    // Important. please don't remove following code.
    // by default, dpdk binds every its lcore thread to its physical cpu
    // with 1:1 mapping, unfortunately curve is not a typical dpdk application,
    // we should unbind it from its core.
    spdk_unaffinitize_thread();
    // end important 

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
    }

    spdk_thread_lib_init(pfs_spdk_schedule_thread,
        sizeof(struct pfs_spdk_thread));

    /* Create an SPDK thread temporarily */
    rc = pfs_spdk_init_thread(&mytd, THREAD_POLL, true);
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

    spdk_log_set_level((spdk_log_level)FLAGS_spdk_log_level);
    spdk_log_set_print_level((spdk_log_level)FLAGS_spdk_log_print_level);

    pthread_mutex_lock(&init_mutex);
    if (!g_spdk_env_initialized) {
        if (pfs_spdk_init_env()) {
            pfs_etrace("failed to initialize\n");
            pthread_mutex_unlock(&init_mutex);
            return -1;
        }

        g_spdk_env_initialized = true;
        atexit(pfs_spdk_cleanup);
        pthread_mutex_unlock(&init_mutex);
    } else {
        pthread_mutex_unlock(&init_mutex);
        return 0;
    }

    pfs_itrace("Found devices:\n");
    for (auto bdev = spdk_bdev_first(); bdev; bdev = spdk_bdev_next(bdev)) {
        std::string cpuset_str;
        cpu_set_t cpuset;
        if (pfs_get_dev_local_cpus(bdev, &cpuset) == 0)
            cpuset_str = pfs_cpuset_to_string(&cpuset);
        pfs_itrace("\tName: %s, Size: %ld, BlockSize: %d, WriteUnit: %d, WriteZero: %d, BufAlign: %ld, Local CPUs: %s",
             spdk_bdev_get_name(bdev),
             spdk_bdev_get_num_blocks(bdev) * spdk_bdev_get_block_size(bdev),
             spdk_bdev_get_block_size(bdev),
             spdk_bdev_get_write_unit_size(bdev),
	     spdk_bdev_io_type_supported(bdev, SPDK_BDEV_IO_TYPE_WRITE_ZEROES),
	     spdk_bdev_get_buf_align(bdev),
             cpuset_str.c_str());
    }
    return 0;
}

void
pfs_spdk_cleanup(void)
{
    int rc;

    pthread_mutex_lock(&init_mutex);
    if (!g_spdk_env_initialized) {
        pthread_mutex_unlock(&init_mutex);
        return;
    }
    pfs_spdk_thread_exit();
    g_poll_exit_result = 0;
    g_poll_loop = false;
    rc = pthread_join(g_init_thread_id, NULL);
    if (rc)
	    pfs_etrace("can not join " THREAD_POLL " thread, %s\n", strerror(rc));
    if (!g_poll_exit_result) {
        spdk_thread_lib_fini(); 
        spdk_env_fini();
        spdk_log_close();
        g_spdk_env_initialized = 0;
    }
    pthread_mutex_unlock(&init_mutex);
}

void pfs_spdk_thread_exit(void)
{
    struct spdk_thread *spdk_td = spdk_get_thread();
    struct pfs_spdk_thread *pfs_td;

    if (spdk_td == NULL)
        return;
    pfs_td = (pfs_spdk_thread *)spdk_thread_get_ctx(spdk_td);
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

void pfs_spdk_conf_set_controller(const char *s)
{
    FLAGS_spdk_nvme_controller = s;
}

int
pfs_get_dev_local_cpus(struct spdk_bdev *bdev, cpu_set_t *set)
{
    std::string pci_addr;

    CPU_ZERO(set);
    pci_addr = pfs_get_dev_pci_address(bdev);
    if (pci_addr.empty())
        return -1;
    return pfs_get_pci_local_cpus(pci_addr, set);
}

static int
json_write_cb(void *cb_ctx, const void *data, size_t size)
{
	FILE *f = (FILE*) cb_ctx;
	size_t rc;

	rc = fwrite(data, 1, size, f);
	return rc == size ? 0 : -1;
}

std::string
pfs_get_dev_pci_address(struct spdk_bdev *bdev)
{
    std::string address;
    std::vector<spdk_json_val> values;
    struct spdk_json_write_ctx *w;
    char *json = NULL, *end;
    size_t json_size = 0;
    ssize_t values_cnt, rc;
    struct spdk_json_val *nvme, *o, *v;
    FILE *f = open_memstream(&json, &json_size);

    if (0) {
err:
        return "";
    }

    w = spdk_json_write_begin(json_write_cb, f, SPDK_JSON_WRITE_FLAG_FORMATTED);
    spdk_json_write_object_begin(w);
    spdk_bdev_dump_info_json(bdev, w);
    spdk_json_write_object_end(w);
    spdk_json_write_end(w);
    fclose(f);
    f = NULL;

    std::unique_ptr<char, decltype(free)*> json_store(json, free);

    rc = spdk_json_parse(json, json_size, NULL, 0, (void **)&end,
            SPDK_JSON_PARSE_FLAG_ALLOW_COMMENTS);
    if (rc < 0) {
        pfs_etrace("Parsing JSON configuration failed (%zd)\n", rc);
        goto err;
    }

    values.resize(rc);

    rc = spdk_json_parse(json, json_size, values.data(), values.size(),
             (void **)&end, SPDK_JSON_PARSE_FLAG_ALLOW_COMMENTS);
    if (rc != values.size()) {
        pfs_etrace("Parsing JSON configuration failed (%zd)\n", rc);
        goto err;
    }

    rc = spdk_json_find_array(values.data(), "nvme", NULL, &nvme);
    if (rc) {
        pfs_etrace("No 'nvme' key in JSON.\n");
        goto err;
    }

    for (o = spdk_json_array_first(nvme); o; o = spdk_json_next(o)) {
        rc = spdk_json_find_string(o, "pci_address", NULL, &v);
        if (rc == 0) {
            char *s = NULL;
            rc = spdk_json_decode_string(v, &s);
            if (rc == 0) {
                address = s;
                free(s);
                break;
            }
        }
    }

    return address;
}

int
pfs_get_pci_local_cpus(const std::string& pci_addr, cpu_set_t *set)
{
    size_t size = 0;
    char *line = NULL;
    std::stack<uint32_t> local_cpus;
    uint32_t mask;
    int widx;
    bool found = false;

    if (pci_addr.empty())
        return -1;

    std::string sys_path=std::string("/sys/bus/pci/devices/") + pci_addr +
        "/local_cpus";
    FILE *fp = fopen(sys_path.c_str(), "r");
    if (fp == NULL) {
        return -1;
    }

    if (getline(&line, &size, fp) == -1) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    char *t, *p = line, *e = NULL;
    while ((t = strsep(&p, ","))) {
        mask = (uint32_t)strtol(t, &e, 16);
        if (*e != '\0' && *e != '\n') {
            pfs_etrace("can not pass cpu list\n");
            return -1;
        }
        local_cpus.push(mask);
    }

    widx = 0;
    while (!local_cpus.empty()) {
        mask = local_cpus.top();
        local_cpus.pop();
        for (int i = 0; i < 32; ++i) {
            if (mask & (1 << i)) {
                int cpu = (widx * 32) + i;
                CPU_SET(cpu, set);
                found = true;
            }
        }
        widx++;
    }

    if (found)
        return 0;
    return -1;
}

std::string
pfs_cpuset_to_string(const cpu_set_t *mask)
{
    int i = 0, j = 0;
    char buf[64];
    std::string s;

    for (i = 0; i < CPU_SETSIZE;) {
        if (CPU_ISSET(i, mask)) {
            int run = 0;
            for (j = i + 1; j < CPU_SETSIZE; j++) {
                if (CPU_ISSET(j, mask)) run++;
                else break;
            }
            if (!run)
                sprintf(buf, "%d,", i);
            else if (run == 1) {
                sprintf(buf, "%d,%d,", i, i + 1);
                i++;
            } else {
                sprintf(buf, "%d-%d,", i, i + run);
                i += run;
            }
            s += buf;
            i = j;
        } else {
            i++;
        }
    }
    if (!s.empty()) {
        s.pop_back(); // remove last ','
    }
    return s;
}

int
pfs_parse_set(const char *input, cpu_set_t *set)
{
	unsigned idx;
	const char *str = input;
	char *end = NULL;
	unsigned min, max;

	CPU_ZERO(set);

	while (isblank(*str))
		str++;

	/* only digit or left bracket is qualify for start point */
	if ((!isdigit(*str) && *str != '(') || *str == '\0')
		return -1;

	/* process single number or single range of number */
	if (*str != '(') {
		errno = 0;
		idx = strtoul(str, &end, 10);
		if (errno || end == NULL || idx >= CPU_SETSIZE)
			return -1;
		else {
			while (isblank(*end))
				end++;

			min = idx;
			max = idx;
			if (*end == '-') {
				/* process single <number>-<number> */
				end++;
				while (isblank(*end))
					end++;
				if (!isdigit(*end))
					return -1;

				errno = 0;
				idx = strtoul(end, &end, 10);
				if (errno || end == NULL || idx >= CPU_SETSIZE)
					return -1;
				max = idx;
				while (isblank(*end))
					end++;
				if (*end != ',' && *end != '\0')
					return -1;
			}

			if (*end != ',' && *end != '\0' &&
			    *end != '@')
				return -1;

			for (idx = RTE_MIN(min, max);
			     idx <= RTE_MAX(min, max); idx++)
				CPU_SET(idx, set);

			return end - input;
		}
	}

	/* process set within bracket */
	str++;
	while (isblank(*str))
		str++;
	if (*str == '\0')
		return -1;

	min = RTE_MAX_LCORE;
	do {

		/* go ahead to the first digit */
		while (isblank(*str))
			str++;
		if (!isdigit(*str))
			return -1;

		/* get the digit value */
		errno = 0;
		idx = strtoul(str, &end, 10);
		if (errno || end == NULL || idx >= CPU_SETSIZE)
			return -1;

		/* go ahead to separator '-',',' and ')' */
		while (isblank(*end))
			end++;
		if (*end == '-') {
			if (min == RTE_MAX_LCORE)
				min = idx;
			else /* avoid continuous '-' */
				return -1;
		} else if ((*end == ',') || (*end == ')')) {
			max = idx;
			if (min == RTE_MAX_LCORE)
				min = idx;
			for (idx = RTE_MIN(min, max);
			     idx <= RTE_MAX(min, max); idx++)
				CPU_SET(idx, set);

			min = RTE_MAX_LCORE;
		} else
			return -1;

		str = end + 1;
	} while (*end != '\0' && *end != ')');

	/*
	 * to avoid failure that tail blank makes end character check fail
	 * in eal_parse_lcores( )
	 */
	while (isblank(*str))
		str++;

	return str - input;
}

static unsigned
pfs_cpu_socket_id(unsigned lcore_id)
{
#define NUMA_NODE_PATH "/sys/devices/system/node" 
    unsigned socket;

    for (socket = 0; socket < RTE_MAX_NUMA_NODES; socket++) {
        char path[PATH_MAX];

        snprintf(path, sizeof(path), "%s/node%u/cpu%u", NUMA_NODE_PATH,
                socket, lcore_id);
        if (access(path, F_OK) == 0)
            return socket;
    }
    return 0;
}

int
pfs_cpuset_socket_id(cpu_set_t *cpusetp)
{
    unsigned cpu = 0;
    int socket_id = SOCKET_ID_ANY;
    int sid;

    if (cpusetp == NULL)
        return SOCKET_ID_ANY;

    do {
        if (!CPU_ISSET(cpu, cpusetp))
            continue;

        if (socket_id == SOCKET_ID_ANY)
            socket_id = pfs_cpu_socket_id(cpu);

        sid = pfs_cpu_socket_id(cpu);
        if (socket_id != sid) {
            socket_id = SOCKET_ID_ANY;
            break;
        }

    } while (++cpu < CPU_SETSIZE);

    return socket_id;
}
