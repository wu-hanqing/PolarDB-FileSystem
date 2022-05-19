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

#include <gflags/gflags.h>
#include <glog/logging.h>

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
pfs_glog_func(int level, const char *file, const char *func, int line,
	const char *fmt, va_list ap)
{
	char buf[8192];

	int glevel = google::GLOG_INFO;
	switch (level) {
	case PFS_TRACE_FATAL:
		glevel = google::GLOG_FATAL;
		break;
	case PFS_TRACE_ERROR:
		glevel = google::GLOG_ERROR;
		break;
	case PFS_TRACE_WARN:
		glevel = google::GLOG_WARNING;
		break;
	case PFS_TRACE_INFO:
		glevel = google::GLOG_INFO;
		break;
	}
	vsnprintf(buf, sizeof(buf), fmt, ap);
	google::LogMessage(file, line, glevel).stream() << buf;
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
	const char *pbdname;
	int err;

	gflags::ParseCommandLineFlags(&argc, &argv, true);
	google::InitGoogleLogging(argv[0]);
	pfs_set_trace_func(pfs_glog_func);
	setup_sigaction();
	if (pfsd_start(1))
		return 1;
	pfsd_wait_stop();
}
