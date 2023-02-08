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

#include <stdlib.h>
#include <string.h>
#include "pfs_stat_file_type.h"

#include "pfs_errno_wrapper.h"

#define FULL_MATCH(a, b) \
	(0 == memcmp((a), (b), sizeof(b) - 1))
#define TAIL_MATCH(a, len, b) \
	(len >= sizeof(b) && FULL_MATCH(a + len - sizeof(b) + 1, b))
#define HEAD_MATCH(a, len, b) \
	(len >= sizeof(b) && FULL_MATCH(a, b))

const char* pfs_file_type_name[FILE_TYPE_COUNT] = {
	[ FILE_PFS_INITED ]  = "unknown",
	[ FILE_PFS_PAXOS ] = "pfs_paxos",
	[ FILE_PFS_JOUNAL ] = "pfs_journal",
	[ FILE_CURVE_CHUNK ] = "curve_chunk",
	[ FILE_CURVE_SNAPSHOT ] = "curve_snapshot",
	[ FILE_CURVE_LOG ] = "curve_log",
	[ FILE_RAFT_META ] = "raft_meta",
	[ FILE_RAFT_LOG_META ] = "raft_log_meta",
	[ FILE_RAFT_SNAPSHOT_MTEA ] = "raft_snapshot_meta",
	[ FILE_CHUNKFILEPOOL_META ] = "curve_chunkfilepool_meta",
	[ FILE_OTHERS ] = "others",
	[ FILE_COLOR_0 ] = "color_red",
	[ FILE_COLOR_1 ] = "color_green"
};

int
pfs_get_file_type(const char* file_path)
{
	const char *file_name = strrchr(file_path, '/'), *tail_str = NULL;
	size_t len = 0;

	if (file_name == NULL) {
		return FILE_OTHERS;
	}
	++file_name;
	len = strlen(file_name) + 1;
	if (HEAD_MATCH(file_name, len, "chunk_")) {
		return FILE_CURVE_CHUNK;
        }

	if (HEAD_MATCH(file_name, len, "snapshot_")) {
		return FILE_CURVE_SNAPSHOT;
        }

	if (HEAD_MATCH(file_name, len, "curve_log_")) {
		return FILE_CURVE_LOG;
	}

	if (HEAD_MATCH(file_name, len, "raftmeta")) {
		return FILE_RAFT_META;
	}

	if (HEAD_MATCH(file_name, len, "log_meta")) {
		return FILE_RAFT_LOG_META;
	}

	if (HEAD_MATCH(file_name, len, "__raft_snapshot_meta")) {
		return FILE_RAFT_SNAPSHOT_MTEA;
	}

	if (HEAD_MATCH(file_name, len, "chunkfilepool.meta")) {
		return FILE_CHUNKFILEPOOL_META;
	}

	return FILE_OTHERS;
}

int
pfs_get_file_type_index(const char* file_type, int file_type_len)
{
	int file_type_index = -1;
	int i;
	if (strlen(file_type) == 0)
		return file_type_index;
	for (i = 0; i < FILE_TYPE_COUNT; ++i) {
		if (strncmp(file_type, pfs_file_type_name[i], file_type_len)
		    == 0) {
			file_type_index = i;
			break;
		}
	}
	return file_type_index;
}

int
pfs_get_file_type_index_pat(char* file_type_pattern, int file_type_len,
    bool *filter)
{
	char *savedptr = NULL, *name = NULL, *tmp = file_type_pattern;
	int result;
	for(result = -1;;file_type_pattern = NULL) {
		name = strtok_r(file_type_pattern, "|", &savedptr);
		if (name == NULL)
			break;
		result = pfs_get_file_type_index(name,
		    tmp + file_type_len - name);
		if (result < 0)
			break;
		if (filter)
			filter[result] = true;
	}
	return result;
}

const char*
pfs_get_file_type_name(int type)
{
	return pfs_file_type_name[type];
}

