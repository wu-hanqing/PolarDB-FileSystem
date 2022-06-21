
set(ExtProjBuildDir ${CMAKE_BINARY_DIR}/thirdparties)
set(ExtProjLocalDir ${ExtProjBuildDir}/local)
set(ExtProjDownloadDir ${CMAKE_CURRENT_LIST_DIR}/download)
set(ExtProjInstallRPath ${ExtProjLocalDir}/lib ${CMAKE_INSTALL_RPATH})

ExternalProject_Add(leveldb_prj
    DOWNLOAD_DIR ${ExtProjDownloadDir}/leveldb
    PREFIX ${ExtProjBuildDir}/leveldb
    URL "https://github.com/google/leveldb/archive/a53934a3ae1244679f812d998a4f16f2c7f309a6.tar.gz"
    URL_HASH MD5=458aba294697d3fa1367a1916e4a72c0
    BUILD_IN_SOURCE 1
        CONFIGURE_COMMAND ""
    BUILD_COMMAND make
    PATCH_COMMAND patch < ${CMAKE_CURRENT_LIST_DIR}/leveldb/leveldb.patch
    INSTALL_COMMAND sh ${CMAKE_CURRENT_LIST_DIR}/leveldb/install_leveldb.sh ${ExtProjBuildDir}/leveldb/src/leveldb_prj ${ExtProjLocalDir}
)
add_library(leveldb SHARED IMPORTED)
set_target_properties(leveldb PROPERTIES IMPORTED_LOCATION ${ExtProjLocalDir}/lib/libleveldb.so)
add_dependencies(leveldb leveldb_prj)

ExternalProject_Add(gtest_prj
    DOWNLOAD_DIR ${ExtProjDownloadDir}/gtest
    PREFIX ${ExtProjBuildDir}/gtest
    URL "http://github.com/google/googletest/archive/refs/tags/release-1.8.0.tar.gz"
    URL_HASH SHA256=58a6f4277ca2bc8565222b3bbd58a177609e9c488e8a72649359ba51450db7d8
    CMAKE_ARGS -DCMAKE_PREFIX_PATH=${ExtProjLocalDir}
               -DCMAKE_INSTALL_PREFIX=${ExtProjLocalDir}
               -DBUILD_GMOCK=ON
)
add_library(gtest STATIC IMPORTED)
set_target_properties(gtest PROPERTIES IMPORTED_LOCATION ${ExtProjLocalDir}/lib/libgtest.a)
add_dependencies(gtest gtest_prj)

add_library(gtest_main STATIC IMPORTED)
set_target_properties(gtest_main PROPERTIES IMPORTED_LOCATION ${ExtProjLocalDir}/lib/libgtest_main.a)
add_dependencies(gtest_main gtest_prj)

add_library(gmock STATIC IMPORTED)
set_target_properties(gmock PROPERTIES IMPORTED_LOCATION ${ExtProjLocalDir}/lib/libgmock.a)
add_dependencies(gmock gtest_prj)

add_library(gmock_main STATIC IMPORTED)
set_target_properties(gmock_main PROPERTIES IMPORTED_LOCATION ${ExtProjLocalDir}/lib/libgmock_main.a)
add_dependencies(gmock_main gtest_prj)

ExternalProject_Add(protobuf_prj
    DOWNLOAD_DIR ${ExtProjDownloadDir}/protobuf
    PREFIX ${ExtProjBuildDir}/protobuf
    URL "https://github.com/google/protobuf/archive/v3.5.0.zip"
    URL_HASH MD5=9e5839297cff6a60a9bcf8c26f0d1f35
    SOURCE_SUBDIR cmake
    CMAKE_ARGS -DCMAKE_CXX_FLAGS=-fPIC
       -Dprotobuf_BUILD_TESTS=OFF
       -DBUILD_SHARED_LIBS=YES
       -DCMAKE_PREFIX_PATH=${ExtProjLocalDir}
       -DCMAKE_INSTALL_PREFIX=${ExtProjLocalDir}
       -DCMAKE_INSTALL_RPATH=${ExtProjInstallRPath}
)
add_library(protobuf SHARED IMPORTED)
set_target_properties(protobuf PROPERTIES IMPORTED_LOCATION ${ExtProjLocalDir}/lib/libprotobuf.so)
add_dependencies(protobuf protobuf_prj)

add_library(protobuf_lite SHARED IMPORTED)
set_target_properties(protobuf_lite PROPERTIES IMPORTED_LOCATION ${ExtProjLocalDir}/lib/libprotobuf_lite.so)
add_dependencies(protobuf_lite protobuf_prj)

ExternalProject_Add(gflags_prj
    DOWNLOAD_DIR ${ExtProjDownloadDir}/gflags
    PREFIX ${ExtProjBuildDir}/gflags
    URL "http://mirror.bazel.build/github.com/gflags/gflags/archive/v2.2.2.tar.gz"
    URL "http://github.com/gflags/gflags/archive/v2.2.2.tar.gz"
    URL_HASH MD5=1a865b93bacfa963201af3f75b7bd64c
    CMAKE_ARGS -DCMAKE_CXX_FLAGS=-fPIC
               -DBUILD_SHARED_LIBS=YES
               -DCMAKE_INSTALL_PREFIX=${ExtProjLocalDir}
               -DCMAKE_INSTALL_RPATH=${ExtProjInstallRPath}
)

add_library(gflags SHARED IMPORTED)
set_target_properties(gflags PROPERTIES IMPORTED_LOCATION ${ExtProjLocalDir}/lib/libgflags.so)
add_dependencies(gflags gflags_prj)

install(FILES
    ${ExtProjLocalDir}/lib/libgflags.so.2.2.2
    DESTINATION
        "${PKG_DIR}/lib"
)

ExternalProject_Add(glog_prj
    DOWNLOAD_DIR ${ExtProjDownloadDir}/glog
    PREFIX ${ExtProjBuildDir}/glog
    URL "http://github.com/google/glog/archive/4cc89c9e2b452db579397887c37f302fb28f6ca1.zip"
    URL_HASH SHA256=2eed7857379bf9d843b2a2fde78e9a746f98dd6ad8ecba902124e79dddf1bd89
    PATCH_COMMAND patch -p1 < ${CMAKE_SOURCE_DIR}/thirdparties/glog/glog.patch
    CMAKE_ARGS -DCMAKE_CXX_FLAGS=-fPIC
               -DBUILD_SHARED_LIBS=YES
               -DCMAKE_PREFIX_PATH=${ExtProjLocalDir}
               -DCMAKE_INSTALL_PREFIX=${ExtProjLocalDir}
               -DCMAKE_INSTALL_RPATH=${ExtProjInstallRPath}
)
add_library(glog SHARED IMPORTED)
set_target_properties (glog PROPERTIES IMPORTED_LOCATION ${ExtProjLocalDir}/lib/libglog.so)
add_dependencies(glog glog_prj)

install(FILES
    ${ExtProjLocalDir}/lib/libglog.so.0.4.0
    DESTINATION
        "${PKG_DIR}/lib"
)

#set(patch_command patch -p1 < ${CMAKE_SOURCE_DIR}/thirdparties/brpc/brpc.patch && patch -p1 < ${CMAKE_SOURCE_DIR}/thirdparties/brpc/brpc_dpdk.patch)
set(patch_command patch -p1 < ${CMAKE_SOURCE_DIR}/thirdparties/brpc/brpc.patch)

ExternalProject_Add(brpc_prj
    DOWNLOAD_DIR ${ExtProjDownloadDir}/brpc
    PREFIX ${ExtProjBuildDir}/brpc
    URL "http://github.com/apache/incubator-brpc/archive/1b9e00641cbec1c8803da6a1f7f555398c954cb0.zip"
    URL_HASH SHA256=811b319a42feb9c1ebb67ab56e1e921a8458f5885f50eba36cf9f2b5dd71daad
    PATCH_COMMAND ${patch_command}
    CMAKE_ARGS -DCMAKE_CXX_FLAGS=-fPIC
        -DBUILD_SHARED_LIBS=YES
        -DWITH_GLOG=ON
        -DWITH_DEBUG_SYMBOLS=ON
        -DCMAKE_VERBOSE_MAKEFILE=ON
        -DCMAKE_INCLUDE_PATH=${ExtProjLocalDir}/include/
        -DCMAKE_PREFIX_PATH=${ExtProjLocalDir}
        -DCMAKE_INSTALL_INCLUDEDIR=${ExtProjLocalDir}/include/
        -DCMAKE_INSTALL_LIBDIR=${ExtProjLocalDir}/lib
        -DCMAKE_INSTALL_RPATH=${ExtProjInstallRPath}
)

foreach(lib brpc)# butil bvar bthread)
  add_library(${lib} SHARED IMPORTED)
  set_target_properties(${lib} PROPERTIES IMPORTED_LOCATION ${ExtProjLocalDir}/lib/lib${lib}.so)
  add_dependencies(${lib} brpc_prj)
endforeach()

add_dependencies(brpc_prj leveldb_prj gflags_prj glog_prj protobuf_prj)
add_dependencies(glog_prj gflags_prj gtest_prj)
add_dependencies(protobuf_prj gflags_prj gtest_prj)

