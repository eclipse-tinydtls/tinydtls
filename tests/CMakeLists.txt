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

project(tinydtls-tests  LANGUAGES C )

if(MSVC)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    # set(COMPILE_OPTIONS -DTEST_INCLUDE -DDTLSv12 -DWITH_SHA256 /Wall /wd4820 /wd4668)
    set(COMPILE_OPTIONS -DTEST_INCLUDE -DDTLSv12 -DWITH_SHA256)
    if(${WARNING_TO_ERROR})
        set(COMPILE_OPTIONS -WX ${COMPILE_OPTIONS})
    endif()
else()
    set(COMPILE_OPTIONS -Wall -DTEST_INCLUDE -DDTLSv12 -DWITH_SHA256)
    if(${WARNING_TO_ERROR})
        set(COMPILE_OPTIONS -Werror ${COMPILE_OPTIONS})
    endif()
    if(APPLE)
        set(COMPILE_OPTIONS -I/opt/homebrew/opt/cunit/include ${COMPILE_OPTIONS})
    endif()
endif()

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

add_executable(dtls-server dtls-server.c dtls_ciphers_util.c)
target_link_libraries(dtls-server LINK_PUBLIC tinydtls)
if(MINGW OR WIN32)
	target_link_libraries(dtls-server LINK_PUBLIC Ws2_32)
endif()
target_compile_options(dtls-server PUBLIC ${COMPILE_OPTIONS})

add_executable(ccm-test ccm-test.c)
target_link_libraries(ccm-test LINK_PUBLIC tinydtls)
if(MINGW OR WIN32)
	target_link_libraries(ccm-test LINK_PUBLIC Ws2_32)
endif()
target_compile_options(ccm-test PUBLIC ${COMPILE_OPTIONS})

add_executable(dtls-client dtls-client.c dtls_ciphers_util.c)
target_link_libraries(dtls-client LINK_PUBLIC tinydtls)
if(MINGW OR WIN32)
	target_link_libraries(dtls-client LINK_PUBLIC Ws2_32)
endif()
target_compile_options(dtls-client PUBLIC ${COMPILE_OPTIONS})

if(NOT MSVC AND NOT MINGW)
    add_executable(testdriver unit-tests/testdriver.c unit-tests/test_ccm.c unit-tests/test_ecc.c unit-tests/test_prf.c)
    target_link_libraries(testdriver LINK_PUBLIC tinydtls)
    if(APPLE)
        target_link_options(testdriver PUBLIC -L/opt/homebrew/opt/cunit/lib)
    endif()
    target_link_libraries(testdriver LINK_PUBLIC cunit)
    target_compile_options(testdriver PUBLIC ${COMPILE_OPTIONS})
endif()
