/* vim: set ts=4 sw=4 expandtab: */

#ifndef _PFS_SPDK_3dee546e_H
#define _PFS_SKDK_3dee546e_H

#include <dpdk/rte_os.h>
#include <spdk/stdinc.h>
#include <spdk/bdev.h>
#include <spdk/thread.h>
#include <spdk/queue.h>

#include <string>
#include <sched.h>

struct pfs_spdk_thread {
};

void pfs_spdk_conf_set_blocked_pci(const char *s);
void pfs_spdk_conf_set_allowed_pci(const char *s);
void pfs_spdk_conf_set_json_config_file(const char *s);
void pfs_spdk_conf_set_name(const char *s);
void pfs_spdk_conf_set_env_context(const char *s);

int  pfs_spdk_setup(void);
void pfs_spdk_cleanup(void);

int pfs_get_pci_local_cpus(const std::string &pci_addr, cpu_set_t *set);
std::string pfs_get_dev_pci_address(struct spdk_bdev *dev);
int pfs_get_dev_local_cpus(struct spdk_bdev *bdev, cpu_set_t *set);
std::string pfs_cpuset_to_string(const cpu_set_t *mask);
int pfs_parse_set(const char *input, rte_cpuset_t *set);

class pfs_spdk_thread_scope {
public:
	pfs_spdk_thread_scope(const char *name="");
	pfs_spdk_thread_scope(struct spdk_thread *thread);
	~pfs_spdk_thread_scope();

	struct spdk_thread *thread() const { return thread_; }
	void detach();
private:
	struct spdk_thread *origin_;
	struct spdk_thread *thread_;
};

#endif
