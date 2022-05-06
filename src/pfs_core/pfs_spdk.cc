#include <semaphore.h>

#include <memory>

#include <spdk/stdinc.h>
#include <spdk/bdev.h>
#include <spdk/env.h>
#include <spdk/init.h>
#include <spdk/thread.h>
#include <spdk/log.h>
#include <spdk/string.h>
#include <spdk/queue.h>
#include <spdk/util.h>

#include <gflags/gflags.h>
#include "pfs_trace.h"

#include "spdk/nvme.h"
#include "spdk/vmd.h"
#include "spdk/nvme_zns.h"
#include "spdk/env.h"
#include "spdk/string.h"
#include "spdk/log.h"

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
DEFINE_uint64(spdk_base_virtaddr, 0, "base virtual base");
DEFINE_string(spdk_env_context, "", "env context string");
DEFINE_string(spdk_json_config_file, "", "spdk json config file");
DEFINE_string(spdk_rpc_addr, SPDK_DEFAULT_RPC_ADDR, "spdk rpc address");
DEFINE_string(spdk_log_flags, "", "spdk log flags");

static pthread_mutex_t g_init_mtx;
static pthread_cond_t g_init_cond;
static bool g_poll_loop = true;
static pthread_t g_init_thread_id;
static int g_spdk_env_initialized;

struct init_param {
	sem_t sem;
	int rc;
};

struct spdk_pfs_thread {
	struct spdk_thread	*spdk_thread; /* spdk thread context */

//	TAILQ_HEAD(, spdk_fio_target)	targets;
	bool			failed; /* true if the thread failed to initialize */

//	struct io_u		**iocq;		/* io completion queue */
//	unsigned int		iocq_count;	/* number of iocq entries filled by last getevents */
//	unsigned int		iocq_size;	/* number of iocq entries allocated */

	TAILQ_ENTRY(spdk_pfs_thread)	link;
};

#define SPDK_FIO_POLLING_TIMEOUT 1000000000ULL
static __thread bool g_internal_thread = false;
static TAILQ_HEAD(, spdk_pfs_thread) g_threads = TAILQ_HEAD_INITIALIZER(g_threads);

static int
spdk_pfs_schedule_thread(struct spdk_thread *spdk_thread)
{
	struct spdk_pfs_thread *thread;

	if (g_internal_thread) {
		/* Do nothing. */
		return 0;
	}

	thread = (struct spdk_pfs_thread *) spdk_thread_get_ctx(spdk_thread);

	pthread_mutex_lock(&g_init_mtx);
	TAILQ_INSERT_TAIL(&g_threads, thread, link);
	pthread_mutex_unlock(&g_init_mtx);

	return 0;
}

static void
parse_pci_address(struct spdk_env_opts *opts)
{
	std::string s;
	char *cp, *t;
	struct spdk_pci_addr **pa;

	if (!FLAGS_spdk_pci_blocked.empty()) {
		s = FLAGS_spdk_pci_blocked;
		pa = &opts->pci_blocked;
	} else {
		s = FLAGS_spdk_pci_allowed;
		pa = &opts->pci_allowed;
	}
	*pa = NULL;

	std::unique_ptr<char, decltype(free)*> store(strdup(s.c_str()), free);

	cp = store.get();
	opts->num_pci_addr = 0;
	while ((t = strsep(&cp, " ,"))) {
		struct spdk_pci_addr addr;
		if (spdk_pci_addr_parse(&addr, t)) {
			pfs_etrace("can not parse pci address: %s\n", t);
		} else {
			*pa = (spdk_pci_addr *)realloc(*pa, sizeof(spdk_pci_addr) * (1 +  opts->num_pci_addr));
			(*pa)[opts->num_pci_addr++] = addr;
		}
	}
}

static void
set_spdk_opts(struct spdk_env_opts *opts)
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
spdk_pfs_bdev_init_done(int rc, void *cb_arg)
{
	*(bool *)cb_arg = true;
}

static void
spdk_pfs_bdev_init_start(void *arg)
{
	bool *done = (bool *) arg;

	spdk_subsystem_init_from_json_config(FLAGS_spdk_json_config_file.c_str(), FLAGS_spdk_rpc_addr.c_str(),
					     spdk_pfs_bdev_init_done, done, true);
}

static int
spdk_pfs_init_thread(struct spdk_pfs_thread **td)
{
	struct spdk_pfs_thread *thread;
	struct spdk_thread *spdk_thread;

	g_internal_thread = true;
	spdk_thread = spdk_thread_create("pfs_thread", NULL);
	g_internal_thread = false;
	if (!spdk_thread) {
		SPDK_ERRLOG("failed to allocate thread\n");
		return -1;
	}

	thread = (spdk_pfs_thread *)spdk_thread_get_ctx(spdk_thread);
	thread->spdk_thread = spdk_thread;

	*td = thread;
	spdk_set_thread(spdk_thread);

#if 0
	fio_thread->iocq_size = td->o.iodepth;
	fio_thread->iocq = calloc(fio_thread->iocq_size, sizeof(struct io_u *));
	assert(fio_thread->iocq != NULL);

	TAILQ_INIT(&fio_thread->targets);
#endif

	return 0;
}

static size_t
spdk_pfs_poll_thread(struct spdk_pfs_thread *thread)
{
	return spdk_thread_poll(thread->spdk_thread, 0, 0);
}

static void
spdk_pfs_bdev_close_targets(void *arg)
{
#if 0
	struct spdk_fio_thread *fio_thread = arg;
	struct spdk_fio_target *target, *tmp;

	TAILQ_FOREACH_SAFE(target, &fio_thread->targets, link, tmp) {
		TAILQ_REMOVE(&fio_thread->targets, target, link);
		spdk_put_io_channel(target->ch);
		spdk_bdev_close(target->desc);
		free(target);
	}
#endif
}

static void
spdk_pfs_cleanup_thread(struct spdk_pfs_thread *thread)
{
	spdk_thread_send_msg(thread->spdk_thread, spdk_pfs_bdev_close_targets, thread);

	pthread_mutex_lock(&g_init_mtx);
	TAILQ_INSERT_TAIL(&g_threads, thread, link);
	pthread_mutex_unlock(&g_init_mtx);
}

static void
spdk_pfs_calc_timeout(struct spdk_pfs_thread *thread, struct timespec *ts)
{
	uint64_t timeout, now;

	if (spdk_thread_has_active_pollers(thread->spdk_thread)) {
		return;
	}

	timeout = spdk_thread_next_poller_expiration(thread->spdk_thread);
	now = spdk_get_ticks();

	if (timeout == 0) {
		timeout = now + (SPDK_FIO_POLLING_TIMEOUT * spdk_get_ticks_hz()) / SPDK_SEC_TO_NSEC;
	}

	if (timeout > now) {
		timeout = ((timeout - now) * SPDK_SEC_TO_NSEC) / spdk_get_ticks_hz() +
			  ts->tv_sec * SPDK_SEC_TO_NSEC + ts->tv_nsec;

		ts->tv_sec  = timeout / SPDK_SEC_TO_NSEC;
		ts->tv_nsec = timeout % SPDK_SEC_TO_NSEC;
	}
}

static void
spdk_pfs_bdev_fini_done(void *cb_arg)
{
	*(bool *)cb_arg = true;
}

static void
spdk_pfs_bdev_fini_start(void *arg)
{
	bool *done = (bool *) arg;

	spdk_subsystem_fini(spdk_pfs_bdev_fini_done, done);
}

static void *
spdk_init_thread_poll(void *arg)
{
	struct init_param *iparam = (struct init_param *)arg;
	struct spdk_env_opts	opts;
	struct spdk_pfs_thread	*mytd, *thread, *tmp;
	struct spdk_thread	*spdk_thread;
	bool			done;
	int			rc;
	struct timespec		ts;

	memset(&opts, 0, sizeof(opts));
	spdk_env_opts_init(&opts);
	set_spdk_opts(&opts);

	if (spdk_env_init(&opts) < 0) {
		SPDK_ERRLOG("Unable to initialize SPDK env\n");
		rc = EINVAL;
		goto err_exit;
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
				SPDK_ERRLOG("unknown spdk log flag %s\n", tok);
				rc = EINVAL;
				goto err_exit;
			}
		} while ((tok = strtok(NULL, ",")) != NULL);
#ifdef DEBUG
		spdk_log_set_print_level(SPDK_LOG_DEBUG);
#endif
	}

	spdk_thread_lib_init(spdk_pfs_schedule_thread, sizeof(struct spdk_pfs_thread));

	/* Create an SPDK thread temporarily */
	rc = spdk_pfs_init_thread(&mytd);
	if (rc < 0) {
		SPDK_ERRLOG("Failed to create initialization thread\n");
		goto err_exit;
	}

	spdk_thread = mytd->spdk_thread;
	/* Initialize the bdev layer */
	done = false;
	spdk_thread_send_msg(spdk_thread, spdk_pfs_bdev_init_start, &done);

        do {
		spdk_pfs_poll_thread(mytd);
        } while (!done);

	/*
	 * Continue polling until there are no more events.
	 * This handles any final events posted by pollers.
	 */
	while (spdk_pfs_poll_thread(mytd) > 0) {}

	iparam->rc = 0;
	sem_post(&iparam->sem);

	while (g_poll_loop) {
		spdk_pfs_poll_thread(mytd);

		pthread_mutex_lock(&g_init_mtx);
		if (!TAILQ_EMPTY(&g_threads)) {
			TAILQ_FOREACH_SAFE(thread, &g_threads, link, tmp) {
				if (spdk_thread_is_exited(thread->spdk_thread)) {
					TAILQ_REMOVE(&g_threads, thread, link);
					//free(thread->iocq);
					spdk_thread_destroy(thread->spdk_thread);
				} else {
					spdk_pfs_poll_thread(thread);
				}
			}

			/* If there are exiting threads to poll, don't sleep. */
			pthread_mutex_unlock(&g_init_mtx);
			continue;
		}

		/* Figure out how long to sleep. */
		clock_gettime(CLOCK_MONOTONIC, &ts);
		spdk_pfs_calc_timeout(mytd, &ts);

		rc = pthread_cond_timedwait(&g_init_cond, &g_init_mtx, &ts);
		pthread_mutex_unlock(&g_init_mtx);

		if (rc != ETIMEDOUT) {
			break;
		}
	}

	spdk_pfs_cleanup_thread(mytd);

	/* Finalize the bdev layer */
	done = false;
	spdk_thread_send_msg(spdk_thread, spdk_pfs_bdev_fini_start, &done);

	do {
		spdk_pfs_poll_thread(mytd);

		TAILQ_FOREACH_SAFE(thread, &g_threads, link, tmp) {
			spdk_pfs_poll_thread(thread);
		}
	} while (!done);

	/* Now exit all the threads */
	TAILQ_FOREACH(thread, &g_threads, link) {
		spdk_set_thread(thread->spdk_thread);
		spdk_thread_exit(thread->spdk_thread);
		spdk_set_thread(NULL);
	}

	/* And wait for them to gracefully exit */
	while (!TAILQ_EMPTY(&g_threads)) {
		TAILQ_FOREACH_SAFE(thread, &g_threads, link, tmp) {
			if (spdk_thread_is_exited(thread->spdk_thread)) {
				TAILQ_REMOVE(&g_threads, thread, link);
				//free(thread->iocq);
				spdk_thread_destroy(thread->spdk_thread);
			} else {
				spdk_thread_poll(thread->spdk_thread, 0, 0);
			}
		}
	}

	pthread_exit(NULL);

err_exit:
	iparam->rc = rc;
	sem_post(&iparam->sem);
	pthread_exit(NULL);
}

static int
spdk_pfs_init_env(void)
{
	struct init_param param;
	int rc;

	sem_init(&param.sem, 0, 0);
	param.rc = -1;

	/*
	 * Spawn a thread to handle initialization operations and to poll things
	 * like the admin queues periodically.
	 */
	rc = pthread_create(&g_init_thread_id, NULL, &spdk_init_thread_poll,
		&param);
	if (rc != 0) {
		SPDK_ERRLOG("Unable to spawn thread to poll admin queue. It won't be polled.\n");
		goto out;
	}

	while (sem_wait(&param.sem) == -1 && errno == EINTR) {}

	rc = param.rc;
out:
	sem_destroy(&param.sem);
	return rc;
}

int
spdk_pfs_setup(void)
{
	if (!g_spdk_env_initialized) {
		if (spdk_pfs_init_env()) {
			SPDK_ERRLOG("failed to initialize\n");
			return -1;
		}

		g_spdk_env_initialized = true;
	}

	struct spdk_bdev *bdev;
	for (bdev = spdk_bdev_first(); bdev; bdev = spdk_bdev_next(bdev)) {
		printf("dev: %s\n", spdk_bdev_get_name(bdev));
		printf("\tsize: %ld\n", spdk_bdev_get_num_blocks(bdev) *
			spdk_bdev_get_block_size(bdev));
	}
	
	return 0;
}
