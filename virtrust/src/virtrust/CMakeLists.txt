# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

add_library(virtrust-obj OBJECT)

find_package(Protobuf REQUIRED)
find_program(GRPC_CPP_PLUGIN grpc_cpp_plugin REQUIRED)

set(VIRTRUST_SOURCE_FILES "")
set(VIRTRUST_PROTO_SOURCE_FILES "")

add_subdirectory(api)
add_subdirectory(base)
add_subdirectory(dllib)
add_subdirectory(crypto)
add_subdirectory(link)
add_subdirectory(utils)

# Object lib

target_sources(virtrust-obj PRIVATE ${VIRTRUST_SOURCE_FILES})

target_include_directories(
  virtrust-obj
  PRIVATE ${CMAKE_DEPS_INCLUDEDIR} $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
          # for pb headers
          ${CMAKE_BINARY_DIR}/src ${CMAKE_CURRENT_BINARY_DIR})

# HACK make sure proto builds before obj
add_dependencies(virtrust-obj virtrust_proto)
add_dependencies(virtrust-obj Deps::spdlog)
add_dependencies(virtrust-obj Deps::secure_c)

# Object protobuf lib

add_library(virtrust_proto OBJECT)
target_sources(virtrust_proto PRIVATE ${VIRTRUST_PROTO_SOURCE_FILES})

protobuf_generate(TARGET virtrust_proto LANGUAGE cpp)

protobuf_generate(
  TARGET
  virtrust_proto
  LANGUAGE
  grpc
  GENERATE_EXTENSIONS
  .grpc.pb.h
  .grpc.pb.cc
  PLUGIN
  "protoc-gen-grpc=${GRPC_CPP_PLUGIN}")

target_link_libraries(
  virtrust_proto
  PRIVATE protobuf
          grpc++
          grpc
          grpc++_reflection
          gpr
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
target_include_directories(virtrust_proto PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

# Shared lib

add_library(virtrust-shared SHARED $<TARGET_OBJECTS:virtrust-obj>
                                   $<TARGET_OBJECTS:virtrust_proto>)

target_include_directories(
  virtrust-shared
  PRIVATE ${CMAKE_DEPS_INCLUDEDIR} ${CMAKE_CURRENT_BINARY_DIR}/src
          $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>)

target_link_libraries(virtrust-shared PRIVATE Deps::spdlog boundscheck)

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
