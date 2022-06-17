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
set(pfsd_VERSION_PATCH 2)
set(pfsd_VERSION 
    ${pfsd_VERSION_MAJOR}.${pfsd_VERSION_MINOR}.${pfsd_VERSION_MATCH})

include(CheckIncludeFile)
include(ExternalProject)
include(FindPkgConfig)
if (NOT PKG_CONFIG_FOUND)
    message(FATAL_ERROR "pkg_config not found")
endif()

set(PKG_DIR "/usr/local/polarstore/pfsd")

include(thirdparties/CMakeLists.txt)

set(DPDK_DIR /usr/local/dpdk CACHE STRING "dpdk directory")
set(SPDK_DIR /usr/local/spdk CACHE STRING "spdk directory")
list(APPEND CMAKE_PREFIX_PATH "${DPDK_DIR}" "${SPDK_DIR}")
set(SANITIZE_ADDRESS OFF CACHE BOOL "enable -fsanitize=address")
set(STACK_PROTECT OFF CACHE BOOL "enable -fstack-protector")

pkg_check_modules(dpdk REQUIRED libdpdk)
include_directories(${dpdk_INCLUDE_DIRS})
link_directories(${dpdk_LIBRARY_DIRS})

pkg_check_modules(spdk_init REQUIRED spdk_init)
include_directories(${spdk_init_INCLUDE_DIRS})
link_directories(${spdk_init_LIBRARY_DIRS})

set(CMAKE_SKIP_BUILD_RPATH FALSE)
set(CMAKE_INSTALL_RPATH ${PKG_DIR}/lib)
#set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

set(SPDK_LIBS
 -Wl,--disable-new-dtags
 -Wl,--push-state
 -Wl,--no-as-needed
 -Wl,--whole-archive
 -Wl,--start-group
 -Bstatic
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

set(COMMON_FLAGS
  -fno-strict-aliasing
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
  -mssse3
  -g
  -D_GNU_SOURCE
  )

if (SANITIZE_ADDRESS)
   list(APPEND COMMON_FLAGS -fsanitize=address)
endif()
if (STACK_PROTECT)
   list(APPEND COMMON_FLAGS -fstack-protector)
endif()

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

string(REPLACE ";" " " CXX_FLAGS "${CXX_FLAGS}")
string(REPLACE ";" " " C_FLAGS "${C_FLAGS}")
string(APPEND CMAKE_CXX_FLAGS "${CXX_FLAGS}")
string(APPEND CMAKE_C_FLAGS "${C_FLAGS}")

message("build log level release level " ${RELEASE_LEVEL} " debug level " ${DEBUG_LEVEL})

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)

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
     ${PROJECT_SOURCE_DIR}/src/pfs_sdk/pfsd_sdk_log.h
     ${PROJECT_SOURCE_DIR}/src/pfs_core/pfs_api.h
     ${PROJECT_SOURCE_DIR}/src/pfs_core/pfs_trace_func.h
     ${PROJECT_SOURCE_DIR}/src/pfs_core/pfs_spdk.h
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
    "${CMAKE_CURRENT_SOURCE_DIR}/package/deb/preinst;${CMAKE_CURRENT_SOURCE_DIR}/package/deb/postinst;${CMAKE_CURRENT_SOURCE_DIR}/package/deb/postrm")
set(CPACK_RPM_PRE_INSTALL_SCRIPT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/package/rpm/preinst")
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/package/rpm/postinst")
set(CPACK_RPM_POST_UNINSTALL_SCRIPT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/package/rpm/postrm")
include(CPack)
