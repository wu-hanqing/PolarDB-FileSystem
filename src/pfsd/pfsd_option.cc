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
#include <string>

#include "pfsd_option.h"
#include "pfsd_common.h"
#include "pfs_option.h"

unsigned int server_id = 0; /* db ins id */

static int FLAGS_daemon;
PFS_OPTION_REG2(daemon, FLAGS_daemon, OPT_INT, "0", NULL);
static int FLAGS_server_id = 0;
PFS_OPTION_REG2(server_id, FLAGS_server_id, OPT_INT, "0", NULL);

static std::string FLAGS_pbd_name;
PFS_OPTION_REG2(pbd_name, FLAGS_pbd_name, OPT_STR, "", NULL);

static std::string FLAGS_shm_dir = PFSD_SHM_PATH;
PFS_OPTION_REG2(shm_dir, FLAGS_shm_dir, OPT_STR, PFSD_SHM_PATH,
	NULL);

static int FLAGS_pollers = 2;
PFS_OPTION_REG2(pollers, FLAGS_pollers, OPT_INT, "2", NULL);

static int FLAGS_workers = 50;
PFS_OPTION_REG2(workers, FLAGS_workers, OPT_INT, "50", NULL);

pfsd_option_t g_pfsd_option;

#define PFSD_TRIM_VALUE(v, min_v, max_v) do {\
	if (v > max_v) \
		v = max_v; \
	else if (v < min_v) \
		v = min_v; \
} while(0)

static bool
sanity_check()
{
	if (strlen(g_pfsd_option.o_pbdname) == 0) {
		pfsd_error("pbdname is empty\n");
		return false;
	}

	return true;
}

static void __attribute__((constructor))
init_default_value()
{
	g_pfsd_option.o_pollers = 2;
	g_pfsd_option.o_workers = 256;
	strncpy(g_pfsd_option.o_shm_dir, PFSD_SHM_PATH, sizeof g_pfsd_option.o_shm_dir);
	g_pfsd_option.o_daemon = 0;
	server_id = 0;
}

int
pfsd_parse_option(void)
{
	g_pfsd_option.o_daemon = FLAGS_daemon;
	g_pfsd_option.o_pollers = FLAGS_pollers;
	g_pfsd_option.o_workers = FLAGS_workers;
	strncpy(g_pfsd_option.o_shm_dir, FLAGS_shm_dir.c_str(), sizeof g_pfsd_option.o_shm_dir);
	strncpy(g_pfsd_option.o_pbdname, FLAGS_pbd_name.c_str(), sizeof g_pfsd_option.o_pbdname);
	server_id = FLAGS_server_id;
	if (!sanity_check())
		return -1;

	return 0;
}
