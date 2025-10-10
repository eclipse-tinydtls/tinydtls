cmake_minimum_required(VERSION 3.10)

find_package(CUnit REQUIRED)

project(testdriver)

add_executable(testdriver
    testdriver.c
    test_ccm.c
    test_ecc.c
    test_prf.c)

target_link_libraries(testdriver PRIVATE tinydtls CUnit::cunit)
if(${WARNING_TO_ERROR})
    target_compile_options(dtls-server PRIVATE $<IF:$<BOOL:${MSVC}>,-WX,-Werror>)
endif()
