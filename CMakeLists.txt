###############################################################################
#
#  Copyright (c) 2022 Contributors to the Eclipse Foundation
#
#  See the LICENSE file(s) distributed with this work for additional
#  information regarding copyright ownership.
#
#  This program and the accompanying materials are made available under the
#  terms of the Eclipse Public License 1.0
#  which is available at https://www.eclipse.org/legal/epl-v10.html
#  and the Eclipse Distribution License v. 1.0
#  available at http://www.eclipse.org/org/documents/edl-v10.php
#
#  SPDX-License-Identifier: EPL-1.0
#
#  Contributors:
#     Jimmy Björklund  - initial version
#     Achim Kraus      - minor fixes
#
###############################################################################

cmake_minimum_required(VERSION 3.10)

project(tinydtls
    VERSION      "0.8.6"
    DESCRIPTION  "A C library for Datagram Transport Layer Security (DTLS) supporting both client and server functionality."
    HOMEPAGE_URL "https://projects.eclipse.org/projects/iot.tinydtls"
    LANGUAGES    C)

set(CMAKE_C_STANDARD 99)

include (AutoConf.cmake)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

if(NOT ZEPHYR_BASE)
   option(BUILD_SHARED_LIBS "Link using shared libs" OFF)
else()
    # provided by the zephyr build system
endif()

option(make_tests "Make test programs and examples" OFF)

if(NOT PLATFORM)
   # PLATFORM seems to be not used
   set(PLATFORM "posix" CACHE STRING "Choose platform." FORCE)
   set_property(CACHE PLATFORM PROPERTY STRINGS "contiki" "espidf" "posix" "riot" "zephyr" "windows")
endif()

set(PACKAGE_NAME    "${PROJECT_NAME}")
set(PACKAGE_VERSION "${PROJECT_VERSION}" )
set(PACKAGE_URL     "${PROJECT_HOMEPAGE_URL}")
set(SOVERSION       "0" )

if(NOT ZEPHYR_BASE)
   option(DTLS_ECC "disable/enable support for TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8" ON )
   option(DTLS_PSK "disable/enable support for TLS_PSK_WITH_AES_128_CCM_8" ON)
else()
   # provided by zephyr/CMakeLists.txt and zephyr/Kconfig
endif()

option(WARNING_TO_ERROR "force all compiler warnings to be errors" OFF)

if(MSVC)
    option(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS "Export all symbols when compiling to a .dll" ON)
endif()

configure_file(dtls_config.h.cmake.in dtls_config.h)

add_library(tinydtls)

target_sources(tinydtls PRIVATE
   dtls.c
   netq.c
   peer.c
   session.c
   crypto.c
   ccm.c
   hmac.c
   dtls_time.c
   dtls_debug.c
   dtls_prng.c
   aes/rijndael.c
   aes/rijndael_wrap.c
   sha2/sha2.c
   ecc/ecc.c)

target_include_directories(tinydtls PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})
target_compile_definitions(tinydtls PUBLIC DTLSv12 WITH_SHA256 SHA2_USE_INTTYPES_H DTLS_CHECK_CONTENTTYPE $<$<BOOL:${make_tests}>:TEST_INCLUDE>)

if(MSVC)
    target_compile_options(tinydtls PRIVATE -Wall -wd4127 -wd4200 -wd4242 -wd4244 -wd4267 -wd4702 -wd4710 -wd4711 -wd4668 -wd4820 -wd5045 -D_CRT_SECURE_NO_WARNINGS)
    if(${WARNING_TO_ERROR})
        target_compile_options(tinydtls PRIVATE -WX)
    endif()
elseif(NOT ZEPHYR_BASE)
    target_compile_options(tinydtls PRIVATE -fPIC -pedantic -std=c99 -Wall -Wextra -Wformat-security -Winline -Wmissing-declarations -Wmissing-prototypes -Wnested-externs -Wpointer-arith -Wshadow -Wstrict-prototypes -Wswitch-default -Wswitch-enum -Wunused)
    if(${WARNING_TO_ERROR})
        target_compile_options(tinydtls PRIVATE -Werror)
    endif()
endif()

set_target_properties(tinydtls PROPERTIES VERSION ${PACKAGE_VERSION} SOVERSION ${SOVERSION})

if( ${make_tests} )
    add_subdirectory(tests)
    add_subdirectory(tests/unit-tests)
    include(CTest)
    add_test(NAME test COMMAND testdriver)
    add_test(NAME ccm-test COMMAND ccm-test)
endif()

if(NOT (${CMAKE_VERSION} VERSION_LESS "3.18.0"))
    file(CONFIGURE OUTPUT .gitignore
        NEWLINE_STYLE UNIX
        CONTENT "*")
endif()

include(GNUInstallDirs)
install(TARGETS tinydtls
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(FILES
    alert.h
    ccm.h
    crypto.h
    dtls.h
    "${CMAKE_CURRENT_BINARY_DIR}/dtls_config.h"
    dtls_debug.h
    dtls_mutex.h
    dtls_prng.h
    dtls_time.h
    global.h
    hmac.h
    netq.h
    numeric.h
    peer.h
    session.h
    state.h
    tinydtls.h
    uthash.h
    utlist.h
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/tinydtls") 
install(FILES
    aes/rijndael.h
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/tinydtls/aes") 
install(FILES
    sha2/sha2.h
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/tinydtls/sha2") 
install(FILES
    ecc/ecc.h
    ecc/test_helper.h
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/tinydtls/ecc")

# pkg-config
set(prefix          "${CMAKE_INSTALL_PREFIX}")
set(exec_prefix     "\${prefix}")
set(includedir      "\${prefix}/include")
set(libdir          "\${exec_prefix}/lib")
configure_file(tinydtls.pc.in tinydtls.pc @ONLY)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/tinydtls.pc"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

# Doxygen
option(ENABLE_DOCS "build Doxygen documentation" ON)
if(ENABLE_DOCS)
    find_package(Doxygen REQUIRED)
    set(DOXYGEN_QUIET YES)
    set(DOXYGEN_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
    set(DOXYGEN_PROJECT_NAME "${PACKAGE_NAME}")
    set(DOXYGEN_PROJECT_NUMBER  "${PACKAGE_VERSION}")
    set(DOXYGEN_RECURSIVE NO)
    set(DOXYGEN_EXTRACT_ALL YES)
    set(DOXYGEN_EXTRACT_STATIC YES)
    set(DOXYGEN_OPTIMIZE_OUTPUT_FOR_C YES)
    set(DOXYGEN_DOT_IMAGE_FORMAT svg)
    set(DOXYGEN_INTERACTIVE_SVG YES)
    doxygen_add_docs(docs
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/aes
        ${CMAKE_CURRENT_SOURCE_DIR}/ecc
        ${CMAKE_CURRENT_SOURCE_DIR}/sha2
        COMMENT "Building Doxygen documentation")
    add_custom_command(TARGET tinydtls POST_BUILD
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target docs)
    install(DIRECTORY
        "${CMAKE_CURRENT_BINARY_DIR}/html/"
        TYPE DOC
        PATTERN "*.md5" EXCLUDE
        PATTERN "*.map" EXCLUDE) 
endif()
