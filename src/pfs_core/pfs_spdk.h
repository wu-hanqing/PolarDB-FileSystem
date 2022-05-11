#ifndef _PFS_SPDK_3dee546e_H
#define _PFS_SKDK_3dee546e_H

#include <spdk/stdinc.h>
#include <spdk/bdev.h>
#include <spdk/thread.h>
#include <spdk/queue.h>

struct pfs_spdk_target {
    struct spdk_bdev_desc *desc;
    struct spdk_io_channel *channel;
    int ref;
    int closed;
    TAILQ_ENTRY(pfs_spdk_target) link;

    pfs_spdk_target();
    ~pfs_spdk_target();
};

struct pfs_spdk_thread {
    struct spdk_thread *spdk_thread;
    TAILQ_HEAD(, pfs_spdk_target) targets;
    TAILQ_ENTRY(pfs_spdk_thread) link;
    int on_pfs_list;
    int	get_count;
    pthread_mutex_t mtx;
};

struct pfs_spdk_thread *pfs_current_spdk_thread(void);

struct spdk_io_channel* pfs_get_spdk_io_channel(struct spdk_bdev_desc *desc);
int pfs_put_spdk_io_channel(struct spdk_io_channel *ch);
void pfs_spdk_close_all_io_channels(struct spdk_bdev_desc *desc);
void pfs_exit_spdk_thread(void);
size_t pfs_spdk_poll_thread(struct pfs_spdk_thread *thread);                      

void pfs_spdk_conf_set_blocked_pci(const char *s);
void pfs_spdk_conf_set_allowed_pci(const char *s);
void pfs_spdk_conf_set_json_config_file(const char *s);
void pfs_spdk_conf_set_name(const char *s);
void pfs_spdk_conf_set_env_context(const char *s);

int pfs_spdk_setup(void);
void pfs_spdk_cleanup(void);

class pfs_spdk_io_channel_guard {
public:
    pfs_spdk_io_channel_guard(struct spdk_bdev_desc *desc) {
        desc_ = desc;
        ch_ = pfs_get_spdk_io_channel(desc);
    }
    ~pfs_spdk_io_channel_guard()
    {
        pfs_put_spdk_io_channel(ch_);
    }

    struct spdk_bdev_desc *desc() const { return desc_; }
    struct spdk_io_channel *channel() const { return ch_; };

private:
    pfs_spdk_io_channel_guard(const pfs_spdk_io_channel_guard &);
    void operator=(const pfs_spdk_io_channel_guard &);

    struct spdk_bdev_desc *desc_;
    struct spdk_io_channel *ch_;
};

#endif
