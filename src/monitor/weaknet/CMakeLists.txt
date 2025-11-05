find_package(DBus1 REQUIRED)
find_package(glog REQUIRED)

file(GLOB common_sources common/*.cpp)
file(GLOB client_sources client/*.cpp) 
file(GLOB server_sources server/*.cpp)

include_directories(common)
include_directories(client)
include_directories(server)
add_library(weaknet ${client_sources} ${common_sources})
target_link_libraries(weaknet 
    glog::glog
    dbus-1
)

add_executable(weaknet_server ${server_sources} ${common_sources})
target_link_libraries(weaknet_server 
    glog::glog
    dbus-1
    agentlinkcoro
)


# tests
file(GLOB_RECURSE SOURCES tests/test_*.cc)

# 循环生成测试可执行文件，输出到 bin/tests
foreach(test ${SOURCES})
    get_filename_component(test_name ${test} NAME_WE)
    x_add_executable(${test_name} ${test} "weaknet")
    set_target_properties(${test_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin/tests/weaknet
    )
endforeach()
