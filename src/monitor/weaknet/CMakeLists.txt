find_package(DBus1 REQUIRED)
find_package(glog REQUIRED)
find_package(ZLIB REQUIRED)

file(GLOB common_sources common/*.cpp)
file(GLOB client_sources client/*.cpp) 
file(GLOB server_sources server/*.cpp)

set(LIBBPF_A ${CMAKE_CURRENT_SOURCE_DIR}/../.output/libbpf.a)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../.output/weaknet/server)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/common)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/client)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/server)

add_library(weaknet ${client_sources} ${common_sources})
target_link_libraries(weaknet 
    glog::glog
    dbus-1
)
add_library(weaknet_server_lib ${server_sources} ${common_sources})
target_link_libraries(weaknet_server_lib PUBLIC
    glog::glog
    dbus-1
    agentlinkcoro
    ${LIBBPF_A}
    elf
    ZLIB::ZLIB
)

add_executable(weaknet_server server/main.cc)
target_link_libraries(weaknet_server weaknet_server_lib)


# tests
file(GLOB_RECURSE SOURCES tests/test_*.cc)

# 循环生成测试可执行文件，输出到 bin/tests
foreach(test ${SOURCES})
    get_filename_component(test_name ${test} NAME_WE)
    x_add_executable(${test_name} ${test} "weaknet_server_lib")
    set_target_properties(${test_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin/tests/weaknet
    )
endforeach()
