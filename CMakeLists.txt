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

cmake_minimum_required(VERSION 3.13)
project(pfsd LANGUAGES CXX C VERSION 2.1.2)

#set default build type to Release
if (NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

include(CheckIncludeFile)
include(ExternalProject)
include(FindPkgConfig)
if (NOT PKG_CONFIG_FOUND)
    message(FATAL_ERROR "pkg_config not found")
endif()

set(PKG_ROOT "/usr/local/curvestore/")
set(PKG_DIR "${PKG_ROOT}/pfsd")

include(thirdparties/CMakeLists.txt)

include_directories(${ExtProjLocalDir}/include SYSTEM)
link_directories(${ExtProjLocalDir}/lib)

set(DPDK_DIR /usr/local/dpdk CACHE STRING "dpdk directory")
set(SPDK_DIR /usr/local/spdk CACHE STRING "spdk directory")
list(APPEND CMAKE_PREFIX_PATH "${DPDK_DIR}" "${SPDK_DIR}")
set(SANITIZE_ADDRESS OFF CACHE BOOL "enable -fsanitize=address")
set(STACK_PROTECT OFF CACHE BOOL "enable -fstack-protector")
set(USE_BTHREAD false CACHE BOOL "enable using bthread")

include_directories(${DPDK_DIR}/include)
link_directories(${DPDK_DIR}/lib)

include_directories(${SPDK_DIR}/include)
link_directories(${SPDK_DIR}/lib)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_SKIP_BUILD_RPATH FALSE)
set(CMAKE_INSTALL_RPATH ${PKG_DIR}/lib)
#set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

if (USE_BTHREAD)
    set(PFS_USE_BTHREAD_VAL 1)
    set(BRPC_LIBS "brpc")
else()
    set(PFS_USE_BTHREAD_VAL 0)
    set(BRPC_LIBS "")
endif()
 
set(SPDK_LIBS
 -Wl,--disable-new-dtags
 -Wl,--push-state
 -Wl,--no-as-needed
 -Wl,--whole-archive
 -Wl,--start-group
 -Bstatic
 spdk_bdev_aio
 spdk_bdev_null
 spdk_bdev_nvme
 spdk_nvme
 spdk_env_dpdk
 spdk_sock_posix
 spdk_event
 spdk_event_bdev
 spdk_bdev
 spdk_notify
 spdk_dma
 spdk_event_accel
 spdk_accel
 spdk_event_vmd
 spdk_vmd
 spdk_event_sock
 spdk_init
 spdk_thread
 spdk_trace
 spdk_sock
 spdk_rpc
 spdk_jsonrpc
 spdk_json
 spdk_util
 spdk_log
 -Wl,--end-group
 -Wl,--no-whole-archive

 -Wl,--whole-archive
 -Wl,--no-as-needed
 -Wl,--start-group
 rte_bus_pci
 rte_cryptodev
 rte_dmadev
 rte_eal
 rte_ethdev
 rte_hash
 rte_kvargs
 rte_mbuf
 rte_mempool
 rte_mempool_ring
 rte_net
 rte_pci
 rte_power
 rte_rcu
 rte_ring
 rte_telemetry
 rte_vhost
 rte_meter
 rte_timer
 rte_stack
 -Wl,--end-group
 -Wl,--no-whole-archive
 -Wl,--pop-state
)

set(SPDK_DEPS uuid numa crypto bsd m aio dl)

include(CMakeLists-config.txt)

message(STATUS "compile pfs for curve nvme storage engine")

include_directories(${CMAKE_CURRENT_LIST_DIR}/src)
include_directories(${ExtProjLocalDir}/include SYSTEM)
link_directories(${ExtProjLocalDir}/lib)

if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    set(CPU_FLAGS "-mssse3")
endif()

set(COMMON_FLAGS
  "-fno-strict-aliasing\
  -Wall\
  -Werror\
  -Wno-deprecated-declarations\
  -Wno-unused-result\
  -Wextra -Wno-unused-parameter\
  -fno-strict-aliasing\
  ${CPU_FLAGS} \
  -g\
  -D_GNU_SOURCE\
  -DPFS_USE_BTHREAD=${PFS_USE_BTHREAD_VAL}\
  -D__PFS_BUILD__"
  )

if (SANITIZE_ADDRESS)
   string(APPEND COMMON_FLAGS " -fsanitize=address")
endif()
if (STACK_PROTECT)
   string(APPEND COMMON_FLAGS " -fstack-protector")
endif()

set(CXX_FLAGS
  "${COMMON_FLAGS}\
  -Wno-sign-compare\
  -Wno-unused-variable\
  -Wno-unused-function"
)

string(APPEND CMAKE_C_FLAGS " ${COMMON_FLAGS}")
string(APPEND CMAKE_CXX_FLAGS " ${COMMON_FLAGS} ${CXX_FLAGS}")
set(CMAKE_CXX_STANDARD 11)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)

add_subdirectory(src)

set(CPACK_PACKAGE_NAME curve-pfsd)
set(CPACK_PACKAGE_VENDOR "Netease")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Polar filesystem")
set(CPACK_PACKAGE_INSTALL_DIRECTORY ${PKG_DIR})
set(CPACK_PACKAGE_VERSION_MAJOR ${pfsd_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${pfsd_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${pfsd_VERSION_PATCH})
set(CPACK_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}-${RAW_GIT_DESC}-${pfsd_VERSION_MAJOR}.${pfsd_VERSION_MINOR}.${pfsd_VERSION_PATCH}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_VERBATIM_VARIABLES TRUE)
set(CPACK_MONOLITHIC_INSTALL TRUE)
set(CPACK_PACKAGE_CONTACT "yfxu@")
set(CPACK_GENERATOR "DEB")
#don't detect nebd library
set(CPACK_RPM_PACKAGE_AUTOREQ FALSE)

file(GLOB pfsd_HEADERS
     ${PROJECT_SOURCE_DIR}/src/pfs_sdk/pfsd_sdk.h
     ${PROJECT_SOURCE_DIR}/src/pfs_sdk/pfsd_sdk_log.h
     ${PROJECT_SOURCE_DIR}/src/pfs_core/pfs_api.h
     ${PROJECT_SOURCE_DIR}/src/pfs_core/pfs_trace_func.h
     ${PROJECT_SOURCE_DIR}/src/pfs_core/pfs_spdk_api.h
     ${PROJECT_SOURCE_DIR}/src/pfs_core/pfs_option_api.h
     ${PROJECT_SOURCE_DIR}/src/pfsd/pfsd.h
)

file(GLOB deploy_FILES
     "${PROJECT_SOURCE_DIR}/deploy_scripts/*"
)

install(
  FILES
	${pfsd_HEADERS}
  DESTINATION "${PKG_DIR}/include")
install(
  FILES
	conf/pfsd_logger.conf
  DESTINATION "${PKG_DIR}/conf")
install(
  FILES
	${deploy_FILES}
  DESTINATION "${PKG_DIR}/bin"
  PERMISSIONS  OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)
  
install(
  FILES
	etc/polarfs.conf
  DESTINATION "${PKG_ROOT}/etc/"
)

set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
    "${CMAKE_CURRENT_SOURCE_DIR}/package/deb/preinst;${CMAKE_CURRENT_SOURCE_DIR}/package/deb/postinst;${CMAKE_CURRENT_SOURCE_DIR}/package/deb/postrm")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "")
set(CPACK_RPM_PRE_INSTALL_SCRIPT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/package/rpm/preinst")
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/package/rpm/postinst")
set(CPACK_RPM_POST_UNINSTALL_SCRIPT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/package/rpm/postrm")
include(CPack)
