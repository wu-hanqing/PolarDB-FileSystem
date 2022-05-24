/*
 * Copyright (c) 2017-2021, Alibaba Group Holding Limited
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <semaphore.h>
#include <fcntl.h>
#include <err.h>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <spdk/log.h>
#include <rte_log.h>

#include "pfsd_common.h"
#include "pfsd_shm.h"
#include "pfsd_worker.h"
#include "pfsd_option.h"
#include "pfsd_chnl.h"
#include "pfsd_log.h"
#include "pfsd.h"

static void
signal_handler(int num)
{
	pfsd_stop();
}

static void
reload_handler(int num)
{
}

void
glog_pfs_func(int level, const char *file, const char *func, int line,
    const char *fmt, va_list ap)
{
    char buf[8192];

    int glevel = google::GLOG_INFO;
    vsnprintf(buf, sizeof(buf), fmt, ap);
    switch (level) {
        case PFS_TRACE_FATAL:
            glevel = google::GLOG_FATAL;
            google::LogMessage(file, line, glevel).stream() << buf;
            abort();
            break;
        case PFS_TRACE_ERROR:
            glevel = google::GLOG_ERROR;
            break;
        case PFS_TRACE_WARN:
            glevel = google::GLOG_WARNING;
            break;
        case PFS_TRACE_INFO:
        default:
            glevel = google::GLOG_INFO;
            break;
    }
    google::LogMessage(file, line, glevel).stream() << buf;
}

void
glog_spdk_func(int level, const char *a_file, const int a_line,
    const char *func, const char *fmt, va_list ap)
{
    char buf[8192];
    const char *file = a_file;
    int line = a_line;

    if (file == NULL) {
        file = "<spdk>";
        if (a_line <= 0)
            line = 1;
    }

    int glevel = google::GLOG_INFO;
    vsnprintf(buf, sizeof(buf), fmt, ap);
    switch(level) {
    case SPDK_LOG_ERROR:
        glevel = google::GLOG_ERROR;
        break;
    case SPDK_LOG_WARN:
    case SPDK_LOG_NOTICE:
        glevel = google::GLOG_WARNING;
        break;
    case SPDK_LOG_INFO:
        glevel = google::GLOG_INFO;
        break;
#ifndef NDEBUG
    case SPDK_LOG_DEBUG:
        glevel = google::GLOG_INFO;
        break;
#endif
    }
    google::LogMessage(file, line, glevel).stream() << buf;
}

static ssize_t
glog_dpdk_log_func(void *cookie, const char *buf, size_t size)
{
    int level = rte_log_cur_msg_loglevel();
    int glevel = google::GLOG_INFO;

    switch(level) {
    case RTE_LOG_EMERG:
    case RTE_LOG_ALERT:
    case RTE_LOG_CRIT:
    case RTE_LOG_ERR:
        glevel = google::GLOG_ERROR;
        break;
    case RTE_LOG_WARNING:
    case RTE_LOG_NOTICE:
        glevel = google::GLOG_WARNING;
        break;
    case RTE_LOG_INFO:
    default:
        glevel = google::GLOG_INFO;
        break;
#ifndef NDEBUG
    case RTE_LOG_DEBUG:
        glevel = google::GLOG_INFO; 
        return 0;
#endif
    }
    google::LogMessage("<dpdk>", 0, glevel).stream().write(buf, size);
    if (level == RTE_LOG_EMERG)
        abort();
    return size;
}

static void setup_sigaction()
{
    /* init signal */
    struct sigaction sig;
    memset(&sig, 0, sizeof(sig));
    sig.sa_handler = signal_handler;
    sigaction(SIGINT, &sig, NULL);
    sig.sa_handler = reload_handler;
    sigaction(SIGHUP, &sig, NULL);
    sig.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sig, NULL);
}

int
main(int argc, char *argv[])
{
    FILE *dpdk_log_stream = NULL;
    cookie_io_functions_t io_funcs;
    memset(&io_funcs, 0, sizeof(io_funcs));

    gflags::ParseCommandLineFlags(&argc, &argv, true);
    google::InitGoogleLogging(argv[0]);
    google::InstallFailureSignalHandler();
    io_funcs.write = glog_dpdk_log_func;
    dpdk_log_stream = fopencookie(NULL, "w", io_funcs);
    if (dpdk_log_stream == NULL) {
        err(1, "fopencookie()");
    }
    rte_openlog_stream(dpdk_log_stream);
    spdk_log_open(glog_spdk_func);
    pfs_set_trace_func(glog_pfs_func);
    setup_sigaction();
    if (pfsd_start(1))
        return 1;
    pfsd_wait_stop();
}
