# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

set(VIRTRUST_SOURCE_FILES
    ${VIRTRUST_SOURCE_FILES}
    ${PROTO_SRC}
    ${CMAKE_CURRENT_LIST_DIR}/grpc_server.cpp
    ${CMAKE_CURRENT_LIST_DIR}/migration_service_impl.cpp
    ${CMAKE_CURRENT_LIST_DIR}/migration_session.cpp)

# Add Mock source files in Fuzz mode
if(ENABLE_MOCK)
    list(APPEND VIRTRUST_SOURCE_FILES
            ${CMAKE_CURRENT_SOURCE_DIR}/mock/grpc_client_mock.cpp
    )
else ()
    list(APPEND VIRTRUST_SOURCE_FILES
            ${CMAKE_CURRENT_LIST_DIR}/grpc_client.cpp
    )
endif()

set(VIRTRUST_PROTO_SOURCE_FILES ${VIRTRUST_PROTO_SOURCE_FILES}
                                ${CMAKE_CURRENT_LIST_DIR}/proto/migrate.proto)

# Add tests for link directory
add_virtrust_test_if(proto_tools_test ${BUILD_TEST})
if(BUILD_TEST)
  target_link_libraries(proto_tools_test PRIVATE virtrust_proto Deps::secure_c)
endif()
add_virtrust_test_if(grpc_client_test ${BUILD_TEST})
if(BUILD_TEST)
  target_link_libraries(grpc_client_test PRIVATE virtrust_proto Deps::secure_c)
endif()
# add_virtrust_test_if(grpc_server_test ${BUILD_TEST})
# add_virtrust_test_if(migration_session_test ${BUILD_TEST}) if(BUILD_TEST)
# target_link_libraries(migration_session_test PRIVATE virtrust_proto) endif()
# add_virtrust_test_if(migration_service_impl_test ${BUILD_TEST}) if(BUILD_TEST)
# target_link_libraries(migration_service_impl_test PRIVATE virtrust_proto)
# endif()

set(VIRTRUST_SOURCE_FILES
    ${VIRTRUST_SOURCE_FILES}
    PARENT_SCOPE)

set(VIRTRUST_PROTO_SOURCE_FILES
    ${VIRTRUST_PROTO_SOURCE_FILES}
    PARENT_SCOPE)
