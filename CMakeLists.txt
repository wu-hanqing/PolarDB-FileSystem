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

cmake_minimum_required (VERSION 3.23.1)
project(pfsd CXX C ASM)
set(pfsd_VERSION_MAJOR 2)
set(pfsd_VERSION_MINOR 1)
set(pfsd_VERSION_PATCH 0)
set(pfsd_VERSION 
    ${pfsd_VERSION_MAJOR}.${pfsd_VERSION_MINOR}.${pfsd_VERSION_MATCH})

include(CheckIncludeFile)

include(FindPkgConfig)
if (NOT PKG_CONFIG_FOUND)
    message(FATAL_ERROR "pkg_config not found")
endif()

find_package(gflags REQUIRED)
include_directories(${GFLAGS_INCLUDE_DIR})
pkg_check_modules(dpdk REQUIRED libdpdk)
pkg_check_modules(spdk_dpdklibs REQUIRED spdk_dpdklibs)
pkg_check_modules(spdk_env_dpdk REQUIRED spdk_env_dpdk)
pkg_check_modules(spdk_init REQUIRED spdk_init)
pkg_check_modules(spdk_log REQUIRED spdk_log)
pkg_check_modules(spdk_bdev REQUIRED spdk_bdev)
pkg_check_modules(spdk_bdev_nvme REQUIRED spdk_bdev_nvme)

set(CMAKE_SKIP_BUILD_RPATH FALSE)
set(CMAKE_INSTALL_RPATH ${dpdk_LIBRARY_DIRS} ${spdk_init_LIBRARY_DIRS})
set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

set(SPDK_LIBS
 -Wl,--push-state
 -Wl,--no-as-needed
 -Wl,--whole-archive
 -Bstatic
 spdk_bdev_null
 spdk_bdev_nvme
 spdk_bdev_passthru
 spdk_bdev_lvol
 spdk_bdev_raid
 spdk_bdev_error
 spdk_bdev_gpt
 spdk_bdev_split
 spdk_bdev_delay
 spdk_bdev_zone_block
 spdk_blobfs_bdev
 spdk_blobfs
 spdk_blob_bdev
 spdk_lvol
 spdk_blob
 spdk_nvme
 spdk_bdev_ftl
 spdk_ftl
 spdk_bdev_aio
 spdk_bdev_virtio
 spdk_virtio
 spdk_accel_ioat
 spdk_ioat
 spdk_scheduler_dynamic
 spdk_env_dpdk
 spdk_scheduler_dpdk_governor
 spdk_scheduler_gscheduler
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
 -Wl,--no-whole-archive

 -Wl,--whole-archive
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
 -Wl,--no-whole-archive
 -Wl,--pop-state
)

message("compile pfsd for PostgreSQL")

include_directories(${CMAKE_CURRENT_LIST_DIR}/src)

set(PKG_DIR "/usr/local/polarstore/pfsd")
#set(CMAKE_BUILD_TYPE "Release")
set(CMAKE_BUILD_TYPE "Debug")

include(CMakeLists-config.txt)

set(COMMON_FLAGS
  -fno-strict-aliasing
  #-fstack-protector
  -fsanitize=address
  #-DEV_STANDALONE
  -Wall
  -Werror
  -Wno-deprecated-declarations
  -Wno-unused-result
  -Wno-format-overflow
  -Wno-misleading-indentation
  -Wno-format-truncation
  -Wno-stringop-truncation
  -Wno-int-in-bool-context
  -Wno-stringop-overflow
  -Wno-error=attributes
  -Wextra -Wno-unused-parameter -Wno-missing-field-initializers
  -Wno-missing-declarations -fno-strict-aliasing
  -Wformat -Wformat-security -Wformat-nonliteral
  -g
  )

if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    set(COMMON_FLAGS ${COMMON_FLAGS}  -march=native -m64)
endif()

set(CMAKE_EXE_LINKER_FLAGS
  # Enable full RELRO - no lazy relocation (resolve everything at load time).
  # This allows the GOT to be made read-only early in the loading process.
  -Wl,-z,relro,-z,now,-z,noexecstack
  # Make the stack non-executable.
  # This is the default in most environments, but it doesn't hurt to set it explicitly.
  #-Wl,-z,noexecstack
)

set(COMMON_FLAGS ${COMMON_FLAGS}  -DPFS_DISK_IO_ONLY)

set(CXX_FLAGS
  ${COMMON_FLAGS}
  -std=c++11
  -Wno-deprecated
  -Wno-unused-local-typedefs
  -Wno-sign-compare
  -fpermissive
  -Wno-unused-variable
  -Wno-unused-function
)

set(C_FLAGS
  ${COMMON_FLAGS}
)

string(REPLACE ";" " " CMAKE_CXX_FLAGS "${CXX_FLAGS}")
string(REPLACE ";" " " CMAKE_C_FLAGS "${C_FLAGS}")

set(CMAKE_CXX_COMPILER "g++")
set(CMAKE_C_COMPILER "cc")

set(DEBUG_LEVEL 20)
set(RELEASE_LEVEL 40)

if(DEFINED ENV{POLAR_LOG_DEBUG_LEVEL})
	set(DEBUG_LEVEL $ENV{POLAR_LOG_DEBUG_LEVEL})
endif()
if(DEFINED ENV{POLAR_LOG_RELEASE_LEVEL})
	set(RELEASE_LEVEL $ENV{POLAR_LOG_RELEASE_LEVEL})
endif()

message("build log level release level " ${RELEASE_LEVEL} " debug level " ${DEBUG_LEVEL})
set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -ggdb -DDEBUG -DCHKSVR_LOG_LEVEL=${DEBUG_LEVEL}")
set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O2 -finline-limit=100000 -DNDEBUG -DCHKSVR_LOG_LEVEL=${RELEASE_LEVEL}")
set(CMAKE_C_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -ggdb -DDEBUG -DCHKSVR_LOG_LEVEL=${DEBUG_LEVEL}")
set(CMAKE_C_FLAGS_RELEASE "$ENV{CXXFLAGS} -O2 -finline-limit=100000 -DNDEBUG -DCHKSVR_LOG_LEVEL=${RELEASE_LEVEL}")

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)

string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE)
message(STATUS "CXX_FLAGS = " ${CMAKE_CXX_FLAGS} " " ${CMAKE_CXX_FLAGS_${BUILD_TYPE}})
message(STATUS "C_FLAGS = " ${CMAKE_C_FLAGS} " " ${CMAKE_C_FLAGS_${BUILD_TYPE}})

execute_process(COMMAND mkdir -p ${PROJECT_SOURCE_DIR}/include)
execute_process(COMMAND cp ${PROJECT_SOURCE_DIR}/src/pfs_sdk/pfsd_sdk.h ${PROJECT_SOURCE_DIR}/include/)

add_subdirectory(src)

set(CPACK_PACKAGE_NAME pfsd)
set(CPACK_PACKAGE_VENDOR "Netease")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Polar filesystem")
set(CPACK_PACKAGE_INSTALL_DIRECTORY pfsd)
set(CPACK_PACKAGE_VERSION_MAJOR ${pfsd_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${pfsd_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${pfsd_VERSION_PATCH})
set(CPACK_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}-${RAW_GIT_DESC}-${pfsd_VERSION_MAJOR}.${pfsd_VERSION_MINOR}.${pfsd_VERSION_PATCH}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_VERBATIM_VARIABLES TRUE)
set(CPACK_MONOLITHIC_INSTALL TRUE)
set(CPACK_PACKAGE_CONTACT "yfxu@")
set(CPACK_GENERATOR "RPM;DEB")
#don't detect nebd library
set(CPACK_RPM_PACKAGE_AUTOREQ FALSE)
file(GLOB pfsd_HEADERS
     ${PROJECT_SOURCE_DIR}/src/pfs_sdk/pfsd_sdk.h
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
	src/pfsd/pfsd.init
  DESTINATION "/etc/init.d/"
  RENAME pfsd_env
)

install(
  FILES
	etc/polarfs.conf
  DESTINATION "/etc/"
)

set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
    "${CMAKE_CURRENT_SOURCE_DIR}/package/deb/preinst;${CMAKE_CURRENT_SOURCE_DIR}/package/deb/postrm")
set(CPACK_RPM_PRE_INSTALL_SCRIPT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/package/rpm/preinst")
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/package/rpm/postinst")
include(CPack)
