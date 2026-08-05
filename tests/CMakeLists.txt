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

project(tinydtls-tests)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(dtls-server dtls-server.c dtls_ciphers_util.c)
target_link_libraries(dtls-server PRIVATE tinydtls $<$<BOOL:${WIN32}>:Ws2_32>)
target_compile_options(dtls-server PRIVATE -Wall -DTEST_INCLUDE -DDTLSv12 -DWITH_SHA256
    $<$<BOOL:${MSVC}>:-wd4200 -wd4242 -wd4244 -wd4267 -wd4388 -wd4710 -wd4711 -wd4668 -wd4820 -wd4996 -wd5045 -D_CRT_SECURE_NO_WARNINGS>)
if(${WARNING_TO_ERROR})
    target_compile_options(dtls-server PRIVATE $<IF:$<BOOL:${MSVC}>,-WX,-Werror>)
endif()

add_executable(ccm-test ccm-test.c)
target_link_libraries(ccm-test PRIVATE tinydtls)
target_compile_options(ccm-test PRIVATE -Wall -DTEST_INCLUDE -DDTLSv12 -DWITH_SHA256
    $<$<BOOL:${MSVC}>:-wd4267 -wd4710 -wd4711 -wd5045>)
if(${WARNING_TO_ERROR})
    target_compile_options(ccm-test PRIVATE $<IF:$<BOOL:${MSVC}>,-WX,-Werror>)
endif()

add_executable(dtls-client dtls-client.c dtls_ciphers_util.c)
target_link_libraries(dtls-client PRIVATE tinydtls $<$<BOOL:${WIN32}>:Ws2_32>)
target_compile_options(dtls-client PRIVATE -Wall -DTEST_INCLUDE -DDTLSv12 -DWITH_SHA256
    $<$<BOOL:${MSVC}>:-wd4200 -wd4242 -wd4244 -wd4267 -wd4388 -wd4710 -wd4711 -wd4668 -wd4820 -wd4996 -wd5045 -D_CRT_SECURE_NO_WARNINGS>)
if(${WARNING_TO_ERROR})
    target_compile_options(dtls-client PRIVATE $<IF:$<BOOL:${MSVC}>,-WX,-Werror>)
endif()

include(GNUInstallDirs)
install(TARGETS dtls-client dtls-server ccm-test
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
