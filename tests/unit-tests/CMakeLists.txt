cmake_minimum_required(VERSION 3.10)

find_package(CUnit REQUIRED)

project(testdriver)

add_executable(testdriver
    testdriver.c
    test_ccm.c
    test_ecc.c
    test_prf.c)

target_link_libraries(testdriver PRIVATE tinydtls CUnit::cunit)
target_compile_options(testdriver PRIVATE -Wall
    $<$<BOOL:${MSVC}>:-wd4267 -wd4464 -wd4710 -wd4820 -wd5045>)
if(${WARNING_TO_ERROR})
    target_compile_options(dtls-server PRIVATE $<IF:$<BOOL:${MSVC}>,-WX,-Werror>)
endif()

if(EXISTS "${CUnit_INCLUDE_DIR}/../bin/cunit.dll")
    add_custom_command(TARGET testdriver POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CUnit_INCLUDE_DIR}/../bin/cunit.dll"
            "$<TARGET_FILE_DIR:testdriver>"
        COMMENT "Copying cunit.dll to test binary directory")
endif()
