# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
add_subdirectory(proto)
get_property(PROTO_SRC GLOBAL PROPERTY PROTO_OUTPUT)

set(VIRTRUST_SOURCE_FILES
    ${VIRTRUST_SOURCE_FILES}
    ${PROTO_SRC}
    ${CMAKE_CURRENT_LIST_DIR}/grpc_server.cpp
    ${CMAKE_CURRENT_LIST_DIR}/migration_service_impl.cpp
    ${CMAKE_CURRENT_LIST_DIR}/grpc_client.cpp
    ${CMAKE_CURRENT_LIST_DIR}/migration_session.cpp)

# add_virtrust_test_if(link_test ${BUILD_TEST})

set(VIRTRUST_SOURCE_FILES
    ${VIRTRUST_SOURCE_FILES}
    PARENT_SCOPE)
