list(APPEND proto_output "${CMAKE_CURRENT_SOURCE_DIR}/migrate.pb.cc"
     "${CMAKE_CURRENT_SOURCE_DIR}/migrate.grpc.pb.cc")

# 创建目录
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/proto)

execute_process(
  COMMAND which grpc_cpp_plugin
  OUTPUT_VARIABLE GRPC_CPP_PLUGIN
  OUTPUT_STRIP_TRAILING_WHITESPACE)

add_custom_command(
  OUTPUT ${proto_output}
  COMMENT "Generating proto file"
  COMMAND
    protoc ARGS --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN} -I
    ${CMAKE_CURRENT_SOURCE_DIR}/ migrate.proto
    --grpc_out=${CMAKE_CURRENT_SOURCE_DIR}/
  COMMAND protoc ARGS -I ${CMAKE_CURRENT_SOURCE_DIR}/ migrate.proto
          --cpp_out=${CMAKE_CURRENT_SOURCE_DIR}/
  VERBATIM
  DEPENDS migrate.proto
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

set_property(GLOBAL PROPERTY PROTO_OUTPUT "${proto_output}")

add_custom_target(build_proto ALL DEPENDS ${proto_output})
