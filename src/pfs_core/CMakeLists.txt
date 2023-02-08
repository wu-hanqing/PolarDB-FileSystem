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
    devio_spdk.cc
    pfs_admin.cc
    pfs_alloc.cc
    pfs_api.cc
    pfs_avl.cc
    pfs_blkio.cc
    pfs_brwlock.cc
    pfs_chunk.cc
    pfs_command.cc
    pfs_config.cc
    pfs_devio.cc
    pfs_devstat.cc
    pfs_dir.cc
    pfs_errno_wrapper.cc
    pfs_file.cc
    pfs_futex_event.cc
    pfs_iomem.cc
    pfs_inode.cc
    pfs_locktable.cc
    pfs_log.cc
    pfs_memory.cc
    pfs_meta.cc
    pfs_mount.cc
    pfs_namecache.cc
    pfs_namei.cc
    pfs_option.cc
    pfs_paxos.cc
    pfs_rangelock.cc
    pfs_spdk.cc
    pfs_stat.cc
    pfs_stat_file_type.cc
    pfs_sync.cc
    pfs_tls.cc
    pfs_trace.cc
    pfs_tx.cc
    pfs_util.cc
    pfs_version.cc
    lib/kstring.c
)

# lib pfs
add_library(pfs STATIC
    ${SRC_LIST}
)
set_property(TARGET pfs PROPERTY POSITION_INDEPENDENT_CODE ON)
if (USE_BTHREAD)
add_dependencies(pfs brpc_prj)
endif()
target_link_libraries(pfs
  aio rt pthread
)

install(TARGETS pfs ARCHIVE DESTINATION "${PKG_DIR}/lib")

