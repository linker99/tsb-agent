# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

set(VIRTRUST_SOURCE_FILES
    ${VIRTRUST_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/file_io.cpp
    ${CMAKE_CURRENT_LIST_DIR}/virt_xml_parser.cpp
    ${CMAKE_CURRENT_LIST_DIR}/migrate_helper.cpp
    ${CMAKE_CURRENT_LIST_DIR}/foreign_mounter.cpp)

add_virtrust_test_if(file_io_test ${BUILD_TEST})
add_virtrust_sh_test_if(virt_xml_parser_test ${BUILD_TEST})
add_virtrust_sh_test_if(foreign_mounter_test ${BUILD_TEST})
add_virtrust_test_if(migrate_helper_test ${BUILD_TEST})

set(VIRTRUST_SOURCE_FILES
    ${VIRTRUST_SOURCE_FILES}
    PARENT_SCOPE)
