/* vim: set ts=4 sw=4 expandtab: */

#include "pfs_spdk.h"
#include "pfs_trace.h"
#include "pfs_memory.h"
#include "pfs_impl.h"

#include <semaphore.h>
#include <memory>
#include <stack>
#include <vector>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <gflags/gflags.h>
#include <dpdk/rte_config.h>
#include <dpdk/rte_os.h>
#include <dpdk/rte_common.h>

#include <spdk/init.h>
#include <spdk/env.h>
#include <spdk/string.h>
#include <spdk/log.h>
#include <spdk/util.h>
#include <spdk/json.h>

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

static bool g_poll_stop = false;
static sem_t g_sem;
static pthread_t g_init_thread_id;
static int g_spdk_env_initialized;

struct init_param {
    sem_t sem;
    int   rc;
};

#define POLLING_TIMEOUT 1000000000ULL

static void
bdev_event_cb(enum spdk_bdev_event_type type, struct spdk_bdev *bdev,
    void *event_ctx)
{
    pfs_etrace("Unsupported bdev event: type %d\n", type);
    return;
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
    return 0;
}

static void
pfs_spdk_calc_timeout(struct spdk_thread *thread, struct timespec *ts)
{
    uint64_t timeout, now;

    if (spdk_thread_has_active_pollers(thread)) {
        return;
    }

    timeout = spdk_thread_next_poller_expiration(thread);
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

static void *
subsys_thread_poll_loop(void *arg)
{
    pfs_spdk_thread_scope spdk_scope((struct spdk_thread *)arg);
    struct spdk_thread *spdk_thread = spdk_scope.thread();
    struct timespec ts;
    int rc;
    bool done;

    pthread_setname_np(pthread_self(), "pfs_spdk_gc");

    while (!g_poll_stop) {
        spdk_thread_poll(spdk_thread, 0, 0);

        /* Figure out how long to sleep. */
        clock_gettime(CLOCK_REALTIME, &ts);
 
        pfs_spdk_calc_timeout(spdk_thread, &ts);

        sem_timedwait(&g_sem, &ts);
    }

    /* Finalize the bdev layer */
    done = false;
    spdk_thread_send_msg(spdk_thread, pfs_spdk_bdev_fini_start, &done);

    do {
        spdk_thread_poll(spdk_thread, 0, 0);
    } while (!done);

    pfs_itrace("spdk bdev subsystem is shutdown now");
    return NULL;
}

static int
pfs_spdk_init_env(void)
{
    struct spdk_env_opts    opts;
    struct spdk_thread      *spdk_thread;
    bool                    done;
    int                     rc;
    struct timespec         ts;

    memset(&opts, 0, sizeof(opts));
    spdk_env_opts_init(&opts);
    set_spdk_opts_from_gflags(&opts);

    if (spdk_env_init(&opts) < 0) {
        pfs_etrace("Unable to initialize SPDK env\n");
        return -1;
    }

    if (!FLAGS_spdk_log_flags.empty()) {
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

    pfs_spdk_thread_scope spdk_scope;

    spdk_thread = spdk_scope.thread();
    /* Initialize the bdev layer */
    done = false;
    spdk_thread_send_msg(spdk_thread, pfs_spdk_bdev_init_start, &done);

    do {
        spdk_thread_poll(spdk_thread, 0, 0);
    } while (!done);

    spdk_scope.detach();

    rc = pthread_create(&g_init_thread_id, NULL, subsys_thread_poll_loop,
            spdk_thread);
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
    int err = 0;

    spdk_log_set_level((spdk_log_level)FLAGS_spdk_log_level);
    spdk_log_set_print_level((spdk_log_level)FLAGS_spdk_log_print_level);

    pthread_mutex_lock(&init_mutex);
    if (!g_spdk_env_initialized) {
        sem_init(&g_sem, 0, 0);
        if (pfs_spdk_init_env()) {
            pfs_etrace("failed to initialize\n");
            pthread_mutex_unlock(&init_mutex);
            return -1;
        } else {
            g_spdk_env_initialized = true;
            err = 0;
        }
    }
    pthread_mutex_unlock(&init_mutex);

    pfs_itrace("found devices:\n");
    struct spdk_bdev *bdev;
    for (bdev = spdk_bdev_first(); bdev; bdev = spdk_bdev_next(bdev)) {
        pfs_itrace("\t name: %s, size: %ld",
                spdk_bdev_get_name(bdev),
                spdk_bdev_get_num_blocks(bdev) * spdk_bdev_get_block_size(bdev));
    }

    return err;
}

void
pfs_spdk_cleanup(void)
{
    struct timespec ts;
    int rc;

    g_poll_stop = true;
    sem_post(&g_sem);
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 5;
    rc = pthread_timedjoin_np(g_init_thread_id, NULL, &ts);
    if (rc) {
        printf("can not join spdk polling thread, %s\n", strerror(rc));
    } else {
        g_spdk_env_initialized = false;
        spdk_env_fini();
        spdk_log_close();
    }
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

int
pfs_get_dev_local_cpus(struct spdk_bdev *bdev, cpu_set_t *set)
{
    std::string pci_addr;

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

    for (i = 0; i < CPU_SETSIZE; i++) {
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
        }
    }
    if (!s.empty()) {
        s.pop_back(); // remove last ','
    }
    return s;
}

/*
 * Parse elem, the elem could be single number/range or '(' ')' group
 * 1) A single number elem, it's just a simple digit. e.g. 9
 * 2) A single range elem, two digits with a '-' between. e.g. 2-6
 * 3) A group elem, combines multiple 1) or 2) with '( )'. e.g (0,2-4,6)
 *    Within group elem, '-' used for a range separator;
 *                       ',' used for a single number.
 */
int
pfs_parse_set(const char *input, rte_cpuset_t *set)
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

pfs_spdk_thread_scope::pfs_spdk_thread_scope(const char *name)
{
    if (!(origin_ = spdk_get_thread())) {
        thread_ = spdk_thread_create(name, NULL);
        PFS_ASSERT(thread_ != NULL);
        spdk_set_thread(thread_);
    } else {
        thread_ = origin_;
    }
}

pfs_spdk_thread_scope::pfs_spdk_thread_scope(struct spdk_thread *thread)
{
    origin_ = spdk_get_thread();
    thread_ = thread;
    spdk_set_thread(thread_);
}

pfs_spdk_thread_scope::~pfs_spdk_thread_scope()
{
    if (origin_ != thread_) {
        spdk_thread_exit(thread_);
        while (!spdk_thread_is_exited(thread_))
            spdk_thread_poll(thread_, 0, 0);
        spdk_thread_destroy(thread_);
        spdk_set_thread(origin_);
    }
}

void
pfs_spdk_thread_scope::detach()
{
    origin_ = thread_;
}
