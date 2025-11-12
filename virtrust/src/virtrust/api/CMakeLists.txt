# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

set(VIRTRUST_SOURCE_FILES
    ${VIRTURST_SOURCE_FILES} ${CMAKE_CURRENT_LIST_DIR}/context.cpp
    ${CMAKE_CURRENT_LIST_DIR}/domain.cpp)

add_virtrust_test_if(domain_test ${BUILD_TEST})

set(VIRTRUST_SOURCE_FILES
    ${VIRTRUST_SOURCE_FILES}
    PARENT_SCOPE)

install(
  FILES ${CMAKE_CURRENT_LIST_DIR}/context.h ${CMAKE_CURRENT_LIST_DIR}/domain.h
        ${CMAKE_CURRENT_LIST_DIR}/defines.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/virtrust/api/
  PERMISSIONS OWNER_READ)
