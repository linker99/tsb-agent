# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

add_library(virtrust-obj OBJECT)

set(VIRTRUST_SOURCE_FILES "")

add_subdirectory(api)
add_subdirectory(base)
add_subdirectory(dllib)
add_subdirectory(crypto)
add_subdirectory(link)
add_subdirectory(utils)
# Object lib

add_dependencies(virtrust-obj build_proto)
target_sources(virtrust-obj PRIVATE ${VIRTRUST_SOURCE_FILES})

target_include_directories(
  virtrust-obj PRIVATE ${CMAKE_DEPS_INCLUDEDIR}
                       $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>)

# Shared lib

add_library(virtrust-shared SHARED $<TARGET_OBJECTS:virtrust-obj>)

target_include_directories(
  virtrust-shared PRIVATE ${CMAKE_DEPS_INCLUDEDIR}
                          $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>)

target_link_libraries(virtrust-shared PRIVATE Deps::spdlog Deps::secure_c)

target_link_libraries(
  virtrust-shared
  PRIVATE grpc++
          grpc++
          grpc
          grpc++_reflection
          gpr
          protobuf
          absl_synchronization
          absl_strings
          absl_str_format_internal
          absl_hash
          absl_cord
          absl_cordz_info
          absl_cordz_functions
          absl_log_internal_check_op
          absl_log_internal_message
          absl_log_internal_nullguard)
