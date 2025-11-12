# Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

set(VIRTRUST_SH_SOURCE_FILES
    ${VIRTRUST_SH_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/op_itf.cpp
    ${CMAKE_CURRENT_LIST_DIR}/op_create.cpp
    ${CMAKE_CURRENT_LIST_DIR}/op_start.cpp
    ${CMAKE_CURRENT_LIST_DIR}/op_migrate.cpp
    ${CMAKE_CURRENT_LIST_DIR}/op_destroy.cpp
    ${CMAKE_CURRENT_LIST_DIR}/op_list.cpp
    ${CMAKE_CURRENT_LIST_DIR}/op_undefine.cpp)

add_virtrust_sh_test_if(op_create_test ${BUILD_TEST})
add_virtrust_sh_test_if(op_start_test ${BUILD_TEST})
add_virtrust_sh_test_if(op_migrate_test ${BUILD_TEST})
add_virtrust_sh_test_if(op_destroy_test ${BUILD_TEST})
add_virtrust_sh_test_if(op_list_test ${BUILD_TEST})
add_virtrust_sh_test_if(op_undefine_test ${BUILD_TEST})

set(VIRTRUST_SH_SOURCE_FILES
    ${VIRTRUST_SH_SOURCE_FILES}
    PARENT_SCOPE)
