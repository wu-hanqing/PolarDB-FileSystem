# Copyright (c) 2017-2021, Alibaba Group Holding Limited
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

include_directories(
    ${PROJECT_SOURCE_DIR}/src/pfs_core/
    ${PROJECT_SOURCE_DIR}/src/pfs_core/lib/
    ${PROJECT_SOURCE_DIR}/src/trace/include/
    )

set(SRC_LIST
    pfs_spdk.cc
    devio_disk.cc
    devio_spdk.cc
    pfs_admin.cc
    pfs_alloc.cc
    pfs_api.cc
    pfs_blkio.cc
    pfs_command.cc
    pfs_config.cc
    pfs_devio.cc
    pfs_devstat.cc
    pfs_dir.cc
    pfs_file.cc
    pfs_inode.cc
    pfs_log.cc
    pfs_memory.cc
    pfs_meta.cc
    pfs_mount.cc
    pfs_namecache.cc
    pfs_namei.cc
    pfs_option.cc
    pfs_paxos.cc
    pfs_stat.cc
    pfs_stat_file_type.cc
    pfs_tls.cc
    pfs_trace.cc
    pfs_tx.cc
    pfs_util.cc
    pfs_version.cc
    pfs_chunk.cc
    pfs_avl.cc
)

# lib pfs
add_library(pfs STATIC
    ${SRC_LIST}
    ${SRC_LIST_LIB}
)

#message("spdk_init_LIB:= ${spdk_init_LIBRARIES}")
#message("spdk_log_LIB:= ${spdk_log_LIBRARIES}")
#message("spdk_bdev_LIB:= ${spdk_bdev_LIBRARIES}")
message("spdk_bdev_nvme_LIB:= ${spdk_bdev_nvme_LIBRARIES}")
#message("spdk_bdev_nvme_LDFLAGS:= ${spdk_bdev_nvme_LDFLAGS}")
message("spdk_env_dpdk_LIB:= ${spdk_env_dpdk_LIBRARIES}")
message("spdk_env_dpdk_LIB:= ${spdk_dpdklibs_LIBRARIES}")

target_include_directories(pfs PUBLIC ${dpdk_INCLUDE_DIRS})
target_include_directories(pfs PUBLIC ${spdk_init_INCLUDE_DIRS})
target_link_directories(pfs PUBLIC ${dpdk_LIBRARY_DIRS})

target_link_libraries(pfs
 gflags numa dl pthread rt uuid crypto m aio
)

set_property(TARGET pfs PROPERTY POSITION_INDEPENDENT_CODE ON)

