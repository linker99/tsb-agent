# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

# 只在 Fuzz 构建类型下启用
if(NOT CMAKE_BUILD_TYPE STREQUAL "Fuzz")
    message(STATUS "Build type is '${CMAKE_BUILD_TYPE}', not 'Fuzz'. Skipping fuzz targets.")
    return()
endif()

# libFuzzer 需要 Clang
if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(WARNING "libFuzzer requires Clang, but current compiler is '${CMAKE_CXX_COMPILER_ID}'. Skipping fuzz targets.")
    return()
endif()

# 添加所有 fuzzer 目标
#add_fuzzer(fuzz_domain_list)
#add_fuzzer(fuzz_domain_create)
#add_fuzzer(fuzz_domain_destroy)
#add_fuzzer(fuzz_domain_migrate)
#add_fuzzer(fuzz_domain_start)
#add_fuzzer(fuzz_domain_undefine)

# 添加统一的fuzzer目标（集成所有domain操作）
add_fuzzer(fuzz_domain_all)

# CLI Fuzzer - 构建时需要包含所有CLI源文件
#option(BUILD_FUZZ_CLI "Build CLI fuzzer" OFF)
#
#if(BUILD_FUZZ_CLI)
# 收集所有CLI源文件
set(CLI_SOURCE_FILES
    ${CMAKE_SOURCE_DIR}/src/virtrust-sh/main.cpp
    ${CMAKE_SOURCE_DIR}/src/virtrust-sh/operator/op_itf.cpp
    ${CMAKE_SOURCE_DIR}/src/virtrust-sh/operator/op_create.cpp
    ${CMAKE_SOURCE_DIR}/src/virtrust-sh/operator/op_start.cpp
    ${CMAKE_SOURCE_DIR}/src/virtrust-sh/operator/op_migrate.cpp
    ${CMAKE_SOURCE_DIR}/src/virtrust-sh/operator/op_destroy.cpp
    ${CMAKE_SOURCE_DIR}/src/virtrust-sh/operator/op_list.cpp
    ${CMAKE_SOURCE_DIR}/src/virtrust-sh/operator/op_undefine.cpp
)

# 创建CLI对象库
add_library(virtrust-sh-fuzz-obj OBJECT ${CLI_SOURCE_FILES})

target_include_directories(virtrust-sh-fuzz-obj PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_DEPS_INCLUDEDIR}
)

target_link_libraries(virtrust-sh-fuzz-obj PRIVATE virtrust-shared)

# 在fuzzing模式下定义必要的宏
target_compile_definitions(virtrust-sh-fuzz-obj PRIVATE
    VIRTRUST_FUZZING_CLI_MODE
    VIRTRUST_MOCK
)

target_compile_options(virtrust-sh-fuzz-obj PRIVATE
    -fsanitize=fuzzer,address,undefined
    -fprofile-instr-generate
    -fcoverage-mapping
)

# 创建CLI fuzzer - 手动创建以支持复杂的依赖关系
add_executable(fuzz_cli fuzz_cli.cpp)

# Apply compiler and linker sanitizer flags (same as add_fuzzer macro)
target_compile_options(fuzz_cli PRIVATE
    -fsanitize=fuzzer,address,undefined
    -fprofile-instr-generate
    -fcoverage-mapping
    -g
)

target_link_options(fuzz_cli PRIVATE
    -fsanitize=fuzzer,address,undefined
    -fprofile-instr-generate
    -fcoverage-mapping
)

# 正确的链接关系：fuzz_cli -> CLI对象库 -> virtrust-shared
target_link_libraries(fuzz_cli PRIVATE virtrust-sh-fuzz-obj)

target_include_directories(fuzz_cli PRIVATE ${CMAKE_DEPS_INCLUDEDIR}
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
)

# Add CTest smoke test if BUILD_TEST is enabled
if(BUILD_TEST)
    include(CTest)
    add_test(NAME fuzz_cli_smoke
            COMMAND fuzz_cli -runs=1000)
endif()
#endif()