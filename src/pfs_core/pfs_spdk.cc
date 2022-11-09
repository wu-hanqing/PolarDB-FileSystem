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
#include "pfs_util.h"
#include "pfs_option.h"

#include <ctype.h>
#include <semaphore.h>
#include <stdlib.h>
#include <string.h>

#include <memory>
#include <stack>
#include <vector>
#include <list>

#include <gflags/gflags.h>

#include <spdk/init.h>
#include <spdk/env.h>
#include <spdk/string.h>
#include <spdk/log.h>
#include <spdk/util.h>
#include <spdk/json.h>
#include <spdk/rpc.h>

#include <sys/user.h>	// For PAGE_SIZE and PAGE_MASK
#include <sys/param.h>  // For roundup

std::string FLAGS_spdk_name;
PFS_OPTION_REG2(spdk_name, FLAGS_spdk_name, OPT_STR, "", NULL);

std::string FLAGS_spdk_core_mask;
PFS_OPTION_REG2(spdk_core_mask, FLAGS_spdk_core_mask, OPT_STR, "", NULL);

int FLAGS_spdk_shm_id = -1;
PFS_OPTION_REG2(spdk_shm_id, FLAGS_spdk_shm_id, OPT_INT, "-1", NULL);

int FLAGS_spdk_mem_channel = -1;
PFS_OPTION_REG2(spdk_mem_channel, FLAGS_spdk_mem_channel, OPT_INT, "-1", NULL);

int FLAGS_spdk_main_core = -1;
PFS_OPTION_REG2(spdk_main_core, FLAGS_spdk_main_core, OPT_INT, "-1", NULL);

int FLAGS_spdk_mem_size = -1;
PFS_OPTION_REG2(spdk_mem_size, FLAGS_spdk_mem_size, OPT_INT, "-1", NULL);

int FLAGS_spdk_no_pci = 0;
PFS_OPTION_REG2(spdk_no_pci, FLAGS_spdk_no_pci, OPT_INT, "0", NULL);

int FLAGS_spdk_hugepage_single_segments = 0;
PFS_OPTION_REG2(spdk_hugepage_single_segments, FLAGS_spdk_hugepage_single_segments,
        OPT_INT, "0", NULL);

int FLAGS_spdk_unlink_hugepage = 0;
PFS_OPTION_REG2(spdk_unlink_hugepage, FLAGS_spdk_unlink_hugepage,
	OPT_INT, "0", NULL);

std::string FLAGS_spdk_hugedir;
PFS_OPTION_REG2(spdk_hugedir, FLAGS_spdk_hugedir, OPT_STR, "", NULL);

std::string FLAGS_spdk_pci_blocked;
PFS_OPTION_REG2(spdk_pci_blocked, FLAGS_spdk_pci_blocked, OPT_STR, "", NULL);

std::string FLAGS_spdk_pci_allowed;
PFS_OPTION_REG2(spdk_pci_allowed, FLAGS_spdk_pci_allowed, OPT_STR, "", NULL);

std::string FLAGS_spdk_iova_mode = "va";
PFS_OPTION_REG2(spdk_iova_mode, FLAGS_spdk_iova_mode, OPT_STR, "va", NULL);

uint64_t FLAGS_spdk_base_virtaddr;
PFS_OPTION_REG2(spdk_base_virtaddr, FLAGS_spdk_base_virtaddr, OPT_LONG, "0", NULL);

std::string FLAGS_spdk_env_context;
PFS_OPTION_REG2(spdk_env_context, FLAGS_spdk_env_context, OPT_STR, "", NULL);

std::string FLAGS_spdk_json_config_file;
PFS_OPTION_REG2(spdk_json_config_file, FLAGS_spdk_json_config_file, OPT_STR, "", NULL);

std::string FLAGS_spdk_rpc_address;
PFS_OPTION_REG2(spdk_rpc_address, FLAGS_spdk_rpc_address, OPT_STR,  "",  NULL);

std::string FLAGS_spdk_log_flags;
// std::string FLAGS_spdk_log_flags = "bdev,thread,nvme";
PFS_OPTION_REG2(spdk_log_flags, FLAGS_spdk_log_flags, OPT_STR,  "", NULL);
//PFS_OPTION_REG2(spdk_log_flags, FLAGS_spdk_log_flags, OPT_STR,  "bdev,thread,nvme", NULL);

int FLAGS_spdk_log_level = SPDK_LOG_INFO;
PFS_OPTION_REG2(spdk_log_level, FLAGS_spdk_log_level, OPT_INT, pfs_to_string(SPDK_LOG_INFO), NULL);

int FLAGS_spdk_log_print_level = SPDK_LOG_INFO;
PFS_OPTION_REG2(spdk_log_print_level, FLAGS_spdk_log_print_level, OPT_INT, pfs_to_string(SPDK_LOG_INFO), NULL);

std::string FLAGS_spdk_nvme_controller;
PFS_OPTION_REG2(spdk_nvme_controller, FLAGS_spdk_nvme_controller, OPT_STR, "", NULL);

int FLAGS_spdk_delete_temp_json_file = 1;
PFS_OPTION_REG2(spdk_delete_temp_json_file, FLAGS_spdk_delete_temp_json_file, OPT_INT, "1", NULL);

static std::string g_spdk_temp_config_file;
static pthread_mutex_t g_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_rpc_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_rpc_cond = PTHREAD_COND_INITIALIZER;
static bool g_rpc_stop = false;
static pthread_mutex_t g_gc_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_gc_cond = PTHREAD_COND_INITIALIZER;
static bool g_gc_stop = false;
static std::list<struct spdk_thread *> g_gc_list;

static bool g_init_stop = false;
static pthread_t g_init_thread_id = 0;
static pthread_t g_rpc_thread_id = 0;
static pthread_t g_gc_thread_id = 0;
static bool g_spdk_env_initialized = false;
struct pfs_spdk_driver_poller spdk_driver_poller = { NULL };

void
pfs_spdk_set_driver_poller(const struct pfs_spdk_driver_poller *poller)
{
    spdk_driver_poller = *poller;
}

void
pfs_spdk_get_driver_poller(struct pfs_spdk_driver_poller *poller)
{
    *poller = spdk_driver_poller;
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

/*
 * Generate json config file base on FLAGS_spdk_nvme_controller
 *
 * Return:
 *    failure:  -1
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
                    "method": "bdev_set_options",
                    "params": {
                        "bdev_io_pool_size": 65535,
                        "bdev_io_cache_size": 2048
                    }
                },
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

struct subsys_init_param {
    int result;
    bool done;
};

static void
pfs_spdk_init_subsys_done(int rc, void *cb_arg)
{
    struct subsys_init_param *param = (struct subsys_init_param *)cb_arg;
    param->result = rc;
    param->done = true;
    if (FLAGS_spdk_delete_temp_json_file) {
        unlink(g_spdk_temp_config_file.c_str());
    }
}

static void
pfs_spdk_init_subsys_start(void *arg)
{
    struct subsys_init_param *param = (struct subsys_init_param *) arg;
    std::string json_file;

    param->result = 0;
    param->done = false;
    json_file = g_spdk_temp_config_file;
    if (json_file.empty()) {
        if (FLAGS_spdk_json_config_file.empty())
            pfs_etrace("json config file is not set!");
        else
            json_file = FLAGS_spdk_json_config_file;
        pfs_itrace("json config file: %s", json_file.c_str());
    }

    spdk_subsystem_init_from_json_config(
        json_file.c_str(),
        SPDK_DEFAULT_RPC_ADDR,
        pfs_spdk_init_subsys_done, param, true);
}

static void
pfs_spdk_calc_timeout(struct spdk_thread *spdk_thread, uint64_t polltime, struct timespec *ts)
{
    uint64_t timeout, now;

    if (spdk_thread_has_active_pollers(spdk_thread)) {
        return;
    }

    timeout = spdk_thread_next_poller_expiration(spdk_thread);
    now = spdk_get_ticks();

    if (timeout == 0) {
        timeout = now + (polltime * spdk_get_ticks_hz()) / SPDK_SEC_TO_NSEC;
    }

    if (timeout > now) {
        timeout = ((timeout - now) * SPDK_SEC_TO_NSEC) / spdk_get_ticks_hz() +
              ts->tv_sec * SPDK_SEC_TO_NSEC + ts->tv_nsec;

        ts->tv_sec  = timeout / SPDK_SEC_TO_NSEC;
        ts->tv_nsec = timeout % SPDK_SEC_TO_NSEC;
    }
}

void
pfs_spdk_gc_thread(struct spdk_thread *spdk_thread)
{
    spdk_thread_exit(spdk_thread);
    if (spdk_get_thread() == spdk_thread)
        spdk_set_thread(NULL);

    // kill spdk thread in gc thread context
    pthread_mutex_lock(&g_gc_mutex);
    g_gc_list.push_back(spdk_thread);
    pthread_cond_broadcast(&g_gc_cond);
    pthread_mutex_unlock(&g_gc_mutex);
}

void
pfs_spdk_teardown_thread(struct spdk_thread *spdk_thread)
{
    // kill spdk thread in current thread context
    spdk_thread_exit(spdk_thread);
    while (!spdk_thread_is_exited(spdk_thread)) {
        spdk_thread_poll(spdk_thread, 0, 0);
    }
    spdk_thread_destroy(spdk_thread);
    spdk_set_thread(NULL);
}

static void *
rpc_service(void *arg)
{
    struct spdk_thread *spdk_thread = NULL;

    pthread_setname_np(pthread_self(), "pfs_spdk_rpc");

    spdk_thread = spdk_thread_create("rpc service", NULL);
    spdk_set_thread(spdk_thread);
    if (!FLAGS_spdk_rpc_address.empty()) {
        if (spdk_rpc_initialize(FLAGS_spdk_rpc_address.c_str())) {
            pfs_etrace("can not init spdk rpc server at : %s",
                       FLAGS_spdk_rpc_address.c_str());

            pfs_spdk_teardown_thread(spdk_thread);
            return NULL;
        } else {
            spdk_rpc_set_state(SPDK_RPC_RUNTIME);
            pfs_itrace("init spdk rpc server at : %s",
                       FLAGS_spdk_rpc_address.c_str());
        }
    }

    struct timespec ts, interval = { 0, 100000000 };
    pthread_mutex_lock(&g_rpc_mutex);
    while (!g_rpc_stop) {
        while (spdk_thread_poll(spdk_thread, 0, 0))
            ;
        clock_gettime(CLOCK_REALTIME, &ts);
        pfs_timespecadd(&ts, &interval, &ts);
        pthread_cond_timedwait(&g_rpc_cond, &g_rpc_mutex, &ts);
    }
    pthread_mutex_unlock(&g_rpc_mutex);

    spdk_rpc_finish();
    pfs_spdk_teardown_thread(spdk_thread);

    return NULL;
}

// spdk-thread gc service
static void *
gc_service(void *arg)
{
    struct spdk_thread *spdk_thread = NULL;

    pthread_setname_np(pthread_self(), "spdk_thread_gc");
    spdk_thread = spdk_thread_create("gc service", NULL);

    pthread_mutex_lock(&g_gc_mutex);
    for (;;) {
        if (g_gc_list.empty() && g_gc_stop)
            break;

        // poll my spdk thread
        spdk_set_thread(spdk_thread);
        spdk_thread_poll(spdk_thread, 0, 0);
        // poll discarded spdk threads
        for (auto it = g_gc_list.begin(); it != g_gc_list.end();) {
            struct spdk_thread *tmp = *it;
            spdk_set_thread(tmp);
            while (spdk_thread_poll(tmp, 0, 0))
                ;
            if (spdk_thread_is_exited(tmp)) {
                it = g_gc_list.erase(it);
                const char *name = spdk_thread_get_name(tmp);
                if (name)
                    pfs_itrace("spdk thread '%s' is garbage collected", name);
                else
                    pfs_itrace("spdk thread %p is garbage collected", tmp);
                spdk_thread_destroy(tmp);
                spdk_set_thread(NULL);
            } else {
                it++;
            }
        }
        spdk_set_thread(spdk_thread);
        // Figure out how long to sleep. 
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        // sleep 0.1 seconds
        pfs_spdk_calc_timeout(spdk_thread, 100000000ULL, &ts);
        pthread_cond_timedwait(&g_gc_cond, &g_gc_mutex, &ts);
    }
    pthread_mutex_unlock(&g_gc_mutex);

    // Kill my spdk thread
    spdk_set_thread(spdk_thread);
    spdk_thread_exit(spdk_thread);
    while (!spdk_thread_is_exited(spdk_thread)) {
        spdk_thread_poll(spdk_thread, 0, 0);
    }
    spdk_thread_destroy(spdk_thread);

    return NULL;
}

static int
pfs_spdk_schedule_thread(struct spdk_thread *spdk_thread)
{
    return 0;
}

struct init_env_param {
    int result;
    sem_t sem;

    init_env_param() {
        result = -1;
        sem_init(&sem, 0, 0);
    }

    ~init_env_param() {
        sem_destroy(&sem);
    }

    void wait() {
        while(sem_wait(&sem))
            ;
    }

    void signal() {
        sem_post(&sem);
    }

    void set_result(int res) {
        result = res;
    }
};

static void
pfs_spdk_subsys_fini_done(void *cb_arg)
{
    *(bool *)cb_arg = true;
}

static void *
pfs_spdk_init_env(void *arg)
{
    struct spdk_env_opts opts;
    struct spdk_thread  *spdk_thread = NULL;
    int                 rc = 0;
    struct init_env_param *param = (struct init_env_param *)arg;
    struct timespec     ts;

    param->set_result(-1);
    if (0) {
out:
        param->signal(); 
        return NULL;
    }
    if (pfs_generate_json_file() < 0) {
        goto out;
    }

    memset(&opts, 0, sizeof(opts));
    spdk_env_opts_init(&opts);
    set_spdk_opts_from_gflags(&opts);

    if (spdk_env_init(&opts) < 0) {
        pfs_etrace("Unable to initialize SPDK env\n");
        goto out;
    }

    // [ Important. please don't remove following code.
    // by default, dpdk binds every its lcore thread to its physical cpu
    // with 1:1 mapping, unfortunately curve is not a typical dpdk application,
    // we should unbind it from its core.
    spdk_unaffinitize_thread();
    // end important ]

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
                goto out;
            }
        } while ((tok = strtok(NULL, ",")) != NULL);
    }

    spdk_thread_lib_init(pfs_spdk_schedule_thread, 0);

    spdk_thread = spdk_thread_create("init", NULL);
    if (spdk_thread == NULL) {
        pfs_etrace("Failed to create initialization thread\n");
        spdk_env_fini();
        goto out;
    }
    spdk_set_thread(spdk_thread);

    // init spdk subsys
    struct subsys_init_param subsys_param;
    subsys_param.result = 0;
    subsys_param.done = false;

    pfs_itrace("Initializing spdk subsystem...");
    spdk_thread_send_msg(spdk_thread, pfs_spdk_init_subsys_start,
                         &subsys_param);
    do {
        spdk_thread_poll(spdk_thread, 0, 0);
    } while (!subsys_param.done);

    param->set_result(subsys_param.result);
    if (subsys_param.result) { 
        pfs_itrace("Initialize spdk subsystem failed, result is %d",
                   subsys_param.result);
        pfs_spdk_teardown_thread(spdk_thread);

        param->signal();
        return 0;
    }

    pfs_itrace("Initialize spdk subsystem success");

    // spdk is inited, signal caller
    param->signal();

    // spdk admin thread should keep running
    while (!g_init_stop) {
        while (spdk_thread_poll(spdk_thread, 0, 0))
            ;
        usleep(500);
    }

    // shutdown spdk subsys
    bool fini_done = false;
    spdk_subsystem_fini(pfs_spdk_subsys_fini_done, &fini_done);
    while (!fini_done) {
        spdk_thread_poll(spdk_thread, 0, 0);
    }
    pfs_spdk_teardown_thread(spdk_thread);
    pfs_itrace("spdk subsystem is shutdown now");
    return 0;
}

static int
pfs_spdk_init_rpc_thread(void)
{
    int rc;

    pfs_itrace("Starting spdk rpc service thread");
    rc = pthread_create(&g_rpc_thread_id, NULL, rpc_service, NULL);
    if (rc) {
        fprintf(stderr, "can not create spdk rpc service thread\n");
    }
    return rc;
}

static int
pfs_spdk_init_gc_thread(void)
{
    int rc;

    pfs_itrace("Starting spdk thread gc service thread");
    rc = pthread_create(&g_gc_thread_id, NULL, gc_service, NULL);
    if (rc) {
        fprintf(stderr, "can not create spdk thread gc service thread\n");
    }
    return rc;
}

static void
pfs_spdk_dump_devices(void)
{
    pfs_itrace("Found devices:\n");
    for (auto bdev = spdk_bdev_first(); bdev; bdev = spdk_bdev_next(bdev)) {
        std::string cpuset_str;
        cpu_set_t cpuset;
        if (pfs_get_dev_local_cpus(bdev, &cpuset) == 0)
            cpuset_str = pfs_cpuset_to_string(&cpuset);
        pfs_itrace("\tName: %s, Size: %ld, BlockSize: %d, PhyBlockSize: %d, OptimalIoBoundary: %d, WriteUnit: %d, WriteZero: %d, BufAlign: %ld, Local CPUs: %s",
             spdk_bdev_get_name(bdev),
             spdk_bdev_get_num_blocks(bdev) * spdk_bdev_get_block_size(bdev),
             spdk_bdev_get_block_size(bdev),
             spdk_bdev_get_physical_block_size(bdev),  
             spdk_bdev_get_optimal_io_boundary(bdev),
             spdk_bdev_get_write_unit_size(bdev),
	         spdk_bdev_io_type_supported(bdev, SPDK_BDEV_IO_TYPE_WRITE_ZEROES),
	         spdk_bdev_get_buf_align(bdev),
             cpuset_str.c_str());
    }
}

int
pfs_spdk_setup(void)
{
    pfs_spdk_thread_guard guard;

    spdk_log_set_level((spdk_log_level)FLAGS_spdk_log_level);
    spdk_log_set_print_level((spdk_log_level)FLAGS_spdk_log_print_level);

    //lock initialization procedure
    pthread_mutex_lock(&g_init_mutex);
    if (g_spdk_env_initialized) {
        pthread_mutex_unlock(&g_init_mutex);
        return 0;
    }

    g_init_stop = false;
    g_rpc_stop = false;
    g_gc_stop = false;

    struct init_env_param param;
    // init spdk asynchornously
    if (pthread_create(&g_init_thread_id, NULL, pfs_spdk_init_env, &param)) {
        pfs_etrace("can not create spdk_init_env thread");
        pthread_mutex_unlock(&g_init_mutex);
        return -1;
    }
    param.wait();
    if (param.result == -1) {
        pfs_etrace("failed to initialize spdk\n");
        pthread_mutex_unlock(&g_init_mutex);
        return -1;
    }

    pfs_spdk_init_rpc_thread();
    pfs_spdk_init_gc_thread();

    g_spdk_env_initialized = true;
    pthread_mutex_unlock(&g_init_mutex);

    pfs_spdk_dump_devices();
    return 0;
}

static void
pfs_spdk_shutdown_init_thread(void)
{
    pfs_itrace("Join spdk admin service thread");
    g_init_stop = true;
    pthread_join(g_init_thread_id, NULL);
}

static void
pfs_spdk_shutdown_rpc_thread(void)
{
    int rc;

    pfs_itrace("Join spdk rpc service thread");
    pthread_mutex_lock(&g_rpc_mutex);
    g_rpc_stop = true;
    pthread_cond_broadcast(&g_rpc_cond);
    pthread_mutex_unlock(&g_rpc_mutex);

    rc = pthread_join(g_rpc_thread_id, NULL);
    if (rc)
	    pfs_etrace("can not join spdk rpc service thread, %s\n", strerror(rc));
}

static void
pfs_spdk_shutdown_gc_thread(void)
{
    int rc;

    pfs_itrace("Join spdk thread gc service thread");
    pthread_mutex_lock(&g_gc_mutex);
    g_gc_stop = true;
    pthread_cond_broadcast(&g_gc_cond);
    pthread_mutex_unlock(&g_gc_mutex);

    rc = pthread_join(g_gc_thread_id, NULL);
    if (rc)
	    pfs_etrace("can not join spdk rpc service thread, %s\n", strerror(rc));
}

void
pfs_spdk_cleanup(void)
{
    pfs_spdk_thread_guard guard;
    int rc;

    pthread_mutex_lock(&g_init_mutex);
    if (!g_spdk_env_initialized) {
        pthread_mutex_unlock(&g_init_mutex);
        return;
    }
    pfs_itrace("Cleaning up spdk...");
    pfs_spdk_shutdown_rpc_thread();
    pfs_spdk_shutdown_init_thread();
    pfs_spdk_shutdown_gc_thread();

    spdk_thread_lib_fini();
    spdk_env_fini();
    spdk_log_close();

    g_spdk_env_initialized = 0;

    pthread_mutex_unlock(&g_init_mutex);
    pfs_itrace("Cleaning up spdk done");
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

static int
__pfs_is_spdk_mem(void *p, size_t size)
{
	char *cp = (char *)p;
	size_t left = size;
	while (left > 0) {
		size_t tmp = left;
		if (spdk_vtophys(cp, &tmp) == SPDK_VTOPHYS_ERROR)
			return 0;
		cp += tmp;
		left -= tmp;
	}

	return 1;
}

static int
__pfs_is_spdk_memv(const struct iovec *iov, int iovcnt)
{
	for (int i = 0; i < iovcnt; ++i) {
		if (!__pfs_is_spdk_mem(iov[i].iov_base, iov[i].iov_len))
			return 0;
	}

	return 1;
}

extern "C" int
pfs_is_spdk_mem(void *p, size_t size)
{
	return __pfs_is_spdk_mem(p, size);
}

extern "C" int
pfs_is_spdk_memv(const struct iovec *iov, int iovcnt)
{
	return __pfs_is_spdk_memv(iov, iovcnt);
}

static inline bool                                                              
_is_page_aligned(uint64_t address, uint64_t page_size)                          
{
    return (address & (page_size - 1)) == 0;
}

/*
 * A simple function to verify if iovec is PRP alignment.
 * Note we don't check if neighbours are contig memory areas,
 * it is enough for us.
 */
int
pfs_iov_is_prp_aligned(const struct iovec *iov, int iovcnt)
{
    uintptr_t addr;
    size_t len;
    int i;

    if (iovcnt == 0)
        return 0;

    if (!__pfs_is_spdk_memv(iov, iovcnt)) // Is not spdk memory
        return 0;

    addr = (uintptr_t)iov[0].iov_base;
    if (iovcnt == 1) {
        // check if dword aligned and size is times of sector size
        return (addr & 3) == 0 && (iov[0].iov_len % 512) == 0;
    }
    addr += iov[0].iov_len;
    if (!_is_page_aligned(addr, PAGE_SIZE)) {
        return 0;
    }

    for (i = 1; i < iovcnt - 1; ++i) {
        // middle page must be page aligned and size is times of page
        addr = (uintptr_t)iov[i].iov_base;
        if (!_is_page_aligned(addr, PAGE_SIZE))
            return 0;
        len = iov[i].iov_len;
        if (len % PAGE_SIZE)
            return 0;
    }

    addr = (uintptr_t)iov[i].iov_base;
    if (!_is_page_aligned(addr, PAGE_SIZE))
        return 0;

    len = iov[i].iov_len;
    if (len % 512)
        return 0;

    return 1;
}

int pfs_is_prp_aligned(const void *addr, size_t len)
{
	struct iovec iov;

	iov.iov_base = (void *)addr;
	iov.iov_len = len;
	return pfs_iov_is_prp_aligned(&iov, 1);
}
