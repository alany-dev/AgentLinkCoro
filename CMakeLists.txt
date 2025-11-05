cmake_minimum_required(VERSION 3.10)
project(AgentLinkCoro CXX C ASM)
enable_language(ASM)

include(cmake/utils.cmake)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON) 

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 功能模块编译开关
option(WITH_REDIS "Enable Redis support" OFF)
option(WITH_ZOOKEEPER "Enable ZooKeeper support" OFF)
option(WITH_PROMETHEUS "Enable Prometheus support" OFF)
option(WITH_KAFKA "Enable Kafka support" OFF)
option(WITH_MYSQL "Enable MySQL support" OFF)
option(WITH_SQLITE3 "Enable SQLite3 support" OFF)

add_compile_options(
    -rdynamic
    -O0                     # O0 debug（开发），O2 release（编译会慢很多）
    -ggdb
    -Wall
    -Wno-builtin-macro-redefined
    -Wno-deprecated
    -Wno-error=deprecated-declarations
    -Werror
    -Wno-unused-function
)

SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)

include_directories(/usr/local/include) 
include_directories(src)
link_directories(/usr/local/lib)

find_package(yaml-cpp REQUIRED)
find_package(jsoncpp REQUIRED)
find_package(protobuf REQUIRED)
find_package(Libevent REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(jemalloc REQUIRED)

# 条件查找依赖库
if(WITH_ZOOKEEPER)
    find_package(zookeeper-client-c REQUIRED)
endif()

if(WITH_PROMETHEUS)
    find_package(prometheus-cpp REQUIRED)
endif()

if(WITH_KAFKA)
    find_package(RdKafka REQUIRED)
endif()

if(WITH_REDIS)
    # find_package(hiredis REQUIRED)
endif()

# 条件查找依赖库
if(WITH_MYSQL)
    find_package(libmysqlclient REQUIRED)
endif()

if(WITH_SQLITE3)
    find_package(SQLite3 REQUIRED)
endif()

# Collect source files, excluding module-specific files that will be added conditionally
file(GLOB_RECURSE SOURCES src/base/*.cpp src/base/*.cc src/base/*.c src/base/*.S src/base/*.s)
list(FILTER SOURCES EXCLUDE REGEX ".*src/base/db/redis\.cc$")
list(FILTER SOURCES EXCLUDE REGEX ".*src/base/db/mysql\.cc$")
list(FILTER SOURCES EXCLUDE REGEX ".*src/base/db/sqlite3\.cc$")
list(FILTER SOURCES EXCLUDE REGEX ".*src/base/net/client/zk_client\.cc$")
list(FILTER SOURCES EXCLUDE REGEX ".*src/base/util/prometheus\.cc$")
list(FILTER SOURCES EXCLUDE REGEX ".*src/base/net/client/kafka_client\.cc$")
list(FILTER SOURCES EXCLUDE REGEX ".*src/base/net/http/servlets/metrics_servlet\.cc$")

# 条件收集各模块源码
if(WITH_MYSQL)
    file(GLOB_RECURSE MYSQL_SOURCES src/base/db/mysql.cc)
    list(APPEND SOURCES ${MYSQL_SOURCES})
endif()

if(WITH_SQLITE3)
    file(GLOB_RECURSE SQLITE3_SOURCES src/base/db/sqlite3.cc)
    list(APPEND SOURCES ${SQLITE3_SOURCES})
endif()

if(WITH_REDIS)
    file(GLOB_RECURSE REDIS_SOURCES src/base/db/redis.cc)
    list(APPEND SOURCES ${REDIS_SOURCES})
endif()

if(WITH_ZOOKEEPER)
    file(GLOB_RECURSE ZK_SOURCES src/base/net/client/zk_client.cc)
    list(APPEND SOURCES ${ZK_SOURCES})
endif()

if(WITH_PROMETHEUS)
    file(GLOB_RECURSE PROMETHEUS_SOURCES src/base/util/prometheus.cc)
    file(GLOB_RECURSE PROMETHEUS_SOURCES src/base/net/http/servlets/metrics_servlet.h)
    list(APPEND SOURCES ${PROMETHEUS_SOURCES})
endif()

if(WITH_KAFKA)
    file(GLOB_RECURSE KAFKA_SOURCES src/base/net/client/kafka_client.cc)
    list(APPEND SOURCES ${KAFKA_SOURCES})
endif()

# Generate protobuf sources
set(PROTOBUF_SOURCES "")
protobufmaker(src/base/net/ns/ns_protobuf.proto PROTOBUF_SOURCES ${CMAKE_CURRENT_BINARY_DIR})
protobufmaker(src/base/net/proto/logserver.proto PROTOBUF_SOURCES ${CMAKE_CURRENT_BINARY_DIR})

# Generate ragel sources
set(RAGEL_SOURCES "")
ragelmaker(src/base/net/http/http11_parser.rl RAGEL_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/base/net/http)
ragelmaker(src/base/net/http/httpclient_parser.rl RAGEL_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/base/net/http)
ragelmaker(src/base/net/uri.rl RAGEL_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/base/net)

# Combine all sources
set(ALL_SOURCES ${SOURCES} ${PROTOBUF_SOURCES} ${RAGEL_SOURCES})

add_library(agentlinkcoro SHARED ${ALL_SOURCES})
force_redefine_file_macro_for_sources(agentlinkcoro)
target_include_directories(agentlinkcoro PUBLIC
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}/src/base/net/ns
    ${CMAKE_CURRENT_BINARY_DIR}/src/base/net/proto
    ${PROTOBUF_INCLUDE_DIRS}
)

# 添加编译定义，用于代码中的条件编译
if(WITH_MYSQL)
    target_compile_definitions(agentlinkcoro PUBLIC WITH_MYSQL)
endif()

if(WITH_SQLITE3)
    target_compile_definitions(agentlinkcoro PUBLIC WITH_SQLITE3)
endif()

if(WITH_REDIS)
    target_compile_definitions(agentlinkcoro PUBLIC WITH_REDIS)
endif()

if(WITH_ZOOKEEPER)
    target_compile_definitions(agentlinkcoro PUBLIC WITH_ZOOKEEPER)
endif()

if(WITH_PROMETHEUS)
    target_compile_definitions(agentlinkcoro PUBLIC WITH_PROMETHEUS)
endif()

if(WITH_KAFKA)
    target_compile_definitions(agentlinkcoro PUBLIC WITH_KAFKA)
endif()

target_link_libraries(agentlinkcoro PUBLIC
    dl
    tbb
    pthread
    yaml-cpp::yaml-cpp 
    JsonCpp::JsonCpp
    protobuf::protobuf 
    libevent::libevent 
    openssl::openssl 
    jemalloc::jemalloc 
)

# 条件链接MySQL和SQLite3库
if(WITH_MYSQL)
    target_link_libraries(agentlinkcoro PUBLIC mysqlclient)
endif()

if(WITH_SQLITE3)
    target_link_libraries(agentlinkcoro PUBLIC sqlite3)
endif()

# 条件链接各模块依赖库
if(WITH_REDIS)
    target_link_libraries(agentlinkcoro PUBLIC hiredis_vip)
endif()

if(WITH_ZOOKEEPER)
    target_link_libraries(agentlinkcoro PUBLIC zookeeper-client-c::zookeeper-client-c)
endif()

if(WITH_PROMETHEUS)
    target_link_libraries(agentlinkcoro PUBLIC prometheus-cpp::prometheus-cpp)
endif()

if(WITH_KAFKA)
    target_link_libraries(agentlinkcoro PUBLIC RdKafka::rdkafka++)
endif()

x_add_executable(main "src/main.cc" "agentlinkcoro")
set_target_properties(main PROPERTIES OUTPUT_NAME "main")

# 条件添加监控模块
if(WITH_PROMETHEUS)
    add_subdirectory(src/monitor/weaknet)
endif()

# add_subdirectory(tests)