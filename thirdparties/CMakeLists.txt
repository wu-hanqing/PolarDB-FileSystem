
set(ExtProjBuildDir ${CMAKE_BINARY_DIR}/thirdparties)
set(ExtProjLocalDir ${ExtProjBuildDir}/local)
set(ExtProjDownloadDir ${CMAKE_CURRENT_LIST_DIR}/download)
set(ExtProjInstallRPath ${ExtProjLocalDir}/lib ${CMAKE_INSTALL_RPATH})

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


