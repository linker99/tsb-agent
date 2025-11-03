# Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

set(VIRTRUST_SOURCE_FILES ${VIRTRUST_SOURCE_FILES}
${CMAKE_CURRENT_LIST_DIR}/sm3.cpp)


add_virtrust_test_if(sm3_test ${BUILD_TEST})

set(VIRTRUST_SOURCE_FILES
    ${VIRTRUST_SOURCE_FILES}
    PARENT_SCOPE)
