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
    ${PROJECT_SOURCE_DIR}/src/pfsd/
    ${PROJECT_SOURCE_DIR}/src/pfs_core/
    ${PROJECT_SOURCE_DIR}/src/trace/include/
)

link_directories(
    ${LIBRARY_OUTPUT_PATH}
)

SET(SRC_LIST
    pfsd_api.cc
    pfsd_chnl.cc
    pfsd_chnl_shm.cc
    pfsd_common.cc
    pfsd_memory.cc
    pfsd_option.cc
    pfsd_shm.cc
    pfsd_worker.cc
    pfsd.cc
)

add_library(pfsd_svr STATIC ${SRC_LIST})
target_compile_definitions(pfsd_svr PUBLIC PFSD_SERVER)
add_dependencies(pfsd_svr glog_prj gflags_prj)
if (USE_BTHREAD)
add_dependencies(pfsd_svr brpc_prj)
endif()

# pfsd daemon
add_executable(pfsdaemon pfsd_main.cc)

target_link_libraries(pfsdaemon
    -Wl,--disable-new-dtags
    -Wl,--push-state
    -Wl,--no-as-needed
    -Wl,--whole-archive
    -Bstatic
    pfsd_svr
    pfs
    -Wl,--no-whole-archive
    -Wl,--pop-state
    ${SPDK_LIBS}
    ${SPDK_DEPS}
    ${BRPC_LIBS}
    glog
    gflags
    pthread
)

add_dependencies(pfsdaemon glog_prj gflags_prj)

target_compile_definitions(pfsdaemon PUBLIC PFSD_SERVER)

SET_TARGET_PROPERTIES(pfsdaemon PROPERTIES LINKER_LANGUAGE CXX)

install(TARGETS pfsdaemon DESTINATION "${PKG_DIR}/bin")
install(TARGETS pfsd_svr DESTINATION "${PKG_DIR}/lib")

