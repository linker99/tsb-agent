# Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

set(VIRTRUST_SOURCE_FILES
    ${VIRTRUST_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/custom_logger.cpp
    ${CMAKE_CURRENT_LIST_DIR}/log_adapt.cpp
    ${CMAKE_CURRENT_LIST_DIR}/str_utils.cpp
    ${CMAKE_CURRENT_LIST_DIR}/exception.cpp)

add_virtrust_test_if(exception_test ${BUILD_TEST})
add_virtrust_test_if(custom_logger_test ${BUILD_TEST})
add_virtrust_test_if(log_adapt_test ${BUILD_TEST})
add_virtrust_test_if(str_utils_test ${BUILD_TEST})

install(
  FILES ${CMAKE_CURRENT_LIST_DIR}/custom_logger.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/virtrust/base
  PERMISSIONS OWNER_READ)

set(VIRTRUST_SOURCE_FILES
    ${VIRTRUST_SOURCE_FILES}
    PARENT_SCOPE)
