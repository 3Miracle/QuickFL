cmake_minimum_required(VERSION 2.8)
project(libhcs)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/.cmake")
set(ICP_ROOT "/home/ustc-8/kai/QAT")   #different for your machine 
include_directories(${ICP_ROOT}/quickassist/include ${ICP_ROOT}/quickassist/include/lac ${ICP_ROOT}/quickassist/lookaside/access_layer/include ${ICP_ROOT}/quickassist/lookaside/access_layer/src/sample_code/functional/include ${ICP_ROOT}/quickassist/utilities/libusdm_drv/ ${ICP_ROOT}/quickassist/lookaside/access_layer/src/sample_code/fips)
add_definitions(-DUSER_SPACE -DDO_CRYPTO -fpermissive)
link_libraries(${ICP_ROOT}/quickassist/lookaside/access_layer/src/sample_code/fips/build/linux_2.6/user_space/fips_sample.a ${ICP_ROOT}/build/libqat_s.so ${ICP_ROOT}/quickassist/utilities/libusdm_drv/linux/build/linux_2.6/user_space/libusdm_drv.a -lpthread -lcrypto -ludev)

#LINK openssl
set(SSL_ROOT "/usr/local/babassl/")  #different for your machine 
include_directories(${SSL_ROOT}/include/ )
link_libraries(${SSL_ROOT}/lib/libssl.so ${SSL_ROOT}/lib/libcrypto.so)

execute_process(COMMAND ${CMAKE_C_COMPILER} -v)
# find_package(GMP REQUIRED)
# find_package(OpenMP)
# if (OPENMP_FOUND)
#     set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
#     set(CMAKE_CXX_FLAGS "${CXXMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
# endif()

set(LIBRARY_NAME "hcs")
set(LIBRARY_DIR "lib/")
set(INCLUDE_DIR "include/")
set(SOURCE_DIR  "src/")
set(TEST_DIR    "test/")
set(BINARY_DIR  "bin/")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${LIBRARY_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BINARY_DIR})

# BEGIN: Project configuration
file(GLOB srcs "src/*.c" "src/com/*.c")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -Wall -Wextra -std=c99 -g")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -Wall -Wextra -std=c++11 -g")

include(TestBigEndian)
test_big_endian(IsBigEndian)
if (${IsBigEndian})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHCS_BIG_ENDIAN")
endif (${IsBigEndian})
# END: Project configuration

# BEGIN: Build commands
add_library(${LIBRARY_NAME} SHARED ${srcs})
target_link_libraries(${LIBRARY_NAME} ${GMP_LIBRARIES})
# END: Build commands

# BEGIN: Install commands
set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY true)
set(CMAKE_INSTALL_PREFIX "/usr/local")
install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${LIBRARY_DIR} DESTINATION lib USE_SOURCE_PERMISSIONS)
install(DIRECTORY ${INCLUDE_DIR} DESTINATION include)
# END: Install commands

# BEGIN: Test commands
enable_testing()
set(CMAKE_CTEST_COMMAND "${CMAKE_CTEST_COMMAND} --verbose")

file(GLOB test_srcs "${TEST_DIR}/test_example.cpp")
add_executable(test_example "${TEST_DIR}/test_example.cpp")
target_link_libraries(test_example hcs qat_s ${GMP_LIBRARIES} ${GMPXX_LIBRARIES})

file(GLOB test_srcs "${TEST_DIR}/test_ex.cpp")
add_executable(test_ex "${TEST_DIR}/test_ex.cpp")
target_link_libraries(test_ex hcs qat_s ${GMP_LIBRARIES} ${GMPXX_LIBRARIES})

file(GLOB test_srcs "${TEST_DIR}/test_exam.cpp")
add_executable(test_exam "${TEST_DIR}/test_exam.cpp")
target_link_libraries(test_exam hcs qat_s ${GMP_LIBRARIES} ${GMPXX_LIBRARIES})

# file(GLOB test_srcs "${TEST_DIR}/*.cpp")
# foreach(f ${test_srcs})
#     get_filename_component(test_prog ${f} NAME_WE)
#     add_executable(${test_prog} "${TEST_DIR}/${test_prog}.cpp")
#     target_link_libraries(${test_prog} hcs qat_s ${GMP_LIBRARIES} ${GMPXX_LIBRARIES})
#     add_test(${test_prog} "${BINARY_DIR}/${test_prog}")
# endforeach()
# EN: Test commands

#BEGIN: Build QHCS_bench
# file(GLOB QHCS_srcs "QHCS_bench/*.cpp")
# add_executable(QHCS_bench ${QHCS_srcs})
# target_link_libraries(QHCS_bench hcs ${GMP_LIBRARIES} qat_s)
# END: Build QHCS_bench

BEGIN: Build Multi-QFL
file(GLOB QFL_srcs "Multi-QFL/*.cpp")
add_executable(Multi-QFL ${QFL_srcs})
target_link_libraries(Multi-QFL hcs ${GMP_LIBRARIES} qat_s)
END: Build Multi-QFL