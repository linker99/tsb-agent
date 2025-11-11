# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

set(VIRTRUST_SOURCE_FILES
    ${VIRTRUST_SOURCE_FILES}
    ${PROTO_SRC}
    ${CMAKE_CURRENT_LIST_DIR}/grpc_server.cpp
    ${CMAKE_CURRENT_LIST_DIR}/migration_service_impl.cpp
    ${CMAKE_CURRENT_LIST_DIR}/grpc_client.cpp
    ${CMAKE_CURRENT_LIST_DIR}/migration_session.cpp)

set(VIRTRUST_PROTO_SOURCE_FILES ${VIRTRUST_PROTO_SOURCE_FILES}
                                ${CMAKE_CURRENT_LIST_DIR}/proto/migrate.proto)

# Add tests for link directory
add_virtrust_test_if(proto_tools_test ${BUILD_TEST})
add_virtrust_test_if(grpc_client_test ${BUILD_TEST})
add_virtrust_test_if(grpc_server_test ${BUILD_TEST})
add_virtrust_test_if(migration_session_test ${BUILD_TEST})
add_virtrust_test_if(migration_service_impl_test ${BUILD_TEST})

set(VIRTRUST_SOURCE_FILES
    ${VIRTRUST_SOURCE_FILES}
    PARENT_SCOPE)

set(VIRTRUST_PROTO_SOURCE_FILES
    ${VIRTRUST_PROTO_SOURCE_FILES}
    PARENT_SCOPE)
