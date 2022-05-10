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
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <gflags/gflags.h>

#include "pfsd_option.h"
#include "pfsd_common.h"
#include "pfs_option.h"

unsigned int server_id = 0; /* db ins id */

DEFINE_bool(daemon, false, "become daemon process");
DEFINE_int32(server_id, 0, "PFSD server id");
DEFINE_string(log_cfg, "pfsd_logger.conf", "ZLOG config file");
DEFINE_string(pbd_name, "", "PBD name");
DEFINE_string(shm_dir, PFSD_SHM_PATH, "pfsd shared memory dir");
DEFINE_int32(pollers, 2, "PFSD pollers");
DEFINE_int32(workers, 256, "PFSD pollers");

pfsd_option_t g_option;

#define PFSD_TRIM_VALUE(v, min_v, max_v) do {\
	if (v > max_v) \
		v = max_v; \
	else if (v < min_v) \
		v = min_v; \
} while(0)

static bool
sanity_check()
{
	if (strlen(g_option.o_pbdname) == 0) {
		fprintf(stderr, "pbdname is empty\n");
		return false;
	}

	fprintf(stderr, "option pbdname %s\n",g_option.o_pbdname);
	fprintf(stderr, "option server id %u\n", server_id);
	fprintf(stderr, "option logconf %s\n",g_option.o_log_cfg);

	return true;
}

static void __attribute__((constructor))
init_default_value()
{
	g_option.o_pollers = 2;
	g_option.o_workers = 256;
	strncpy(g_option.o_log_cfg, "pfsd_logger.conf", sizeof g_option.o_log_cfg);
	strncpy(g_option.o_shm_dir, PFSD_SHM_PATH, sizeof g_option.o_shm_dir);
	g_option.o_daemon = 0;
	server_id = 0;
}

int
pfsd_parse_option(int ac, char *av[])
{
	g_option.o_daemon = FLAGS_daemon;
	g_option.o_pollers = FLAGS_pollers;
	g_option.o_workers = FLAGS_workers;
	strncpy(g_option.o_log_cfg, FLAGS_log_cfg.c_str(), sizeof g_option.o_log_cfg);
	strncpy(g_option.o_shm_dir, FLAGS_shm_dir.c_str(), sizeof g_option.o_shm_dir);
	strncpy(g_option.o_pbdname, FLAGS_pbd_name.c_str(), sizeof g_option.o_pbdname);
	server_id = FLAGS_server_id;
	if (!sanity_check())
		return -1;

	return 0;
}
