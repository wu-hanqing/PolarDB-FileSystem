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

cmake_minimum_required (VERSION 2.8)
project(pfsd CXX C ASM)
set(pfsd_VERSION_MAJOR 2)
set(pfsd_VERSION_MINOR 1)
set(pfsd_VERSION_PATCH 5)
set(pfsd_VERSION 
    ${pfsd_VERSION_MAJOR}.${pfsd_VERSION_MINOR}.${pfsd_VERSION_MATCH})

include(CheckIncludeFile)

message("compile pfsd for PostgreSQL")

set(PKG_DIR "/usr/local/polarstore/pfsd")
set(CMAKE_BUILD_TYPE "Release")
#set(CMAKE_BUILD_TYPE "Debug")

include(CMakeLists-config.txt)

link_directories(/usr/lib/curve)
set(CMAKE_INSTALL_RPATH /usr/lib/curve)
set(CURVE_LIBS -lcbd -lcurve_client -lcurve_common -lcurve_auth -lcurve_concurrent
    -lnameserver2_proto -ltopology_proto -lchunkserver-protos -lbrpc -lbutil -lbvar
    -lbthread -lcc_brpc_internal_proto -ljson2pb -lmcpack2pb -lcc_brpc_idl_options_proto
    -lcommon_proto 
    -lprotobuf -lprotobuf_lite -lrt -lssl -lcrypto -ldl -lz -lpthread -lleveldb -lgflags -lglog)

set(COMMON_FLAGS
  -fno-strict-aliasing
  #-fstack-protector
  #-fsanitize=address
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
