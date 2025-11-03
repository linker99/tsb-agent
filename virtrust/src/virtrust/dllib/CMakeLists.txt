# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

set(VIRTRUST_SOURCE_FILES ${VIRTRUST_SOURCE_FILES})

# add_virtrust_test_if(libxml2_test ${BUILD_TEST})

# HACK libguestfs has memory leaks, so we disable this test under asan
#
# if(NOT CMAKE_BUILD_TYPE STREQUAL "Asan") add_virtrust_test_if(libguestfs_test
# ${BUILD_TEST}) endif()

# add_virtrust_test_if(libvirt_test ${BUILD_TEST})
# add_virtrust_test_if(openssl_test ${BUILD_TEST})
# add_virtrust_test_if(dllib_test ${BUILD_TEST})

set(VIRTRUST_SOURCE_FILES
    ${VIRTRUST_SOURCE_FILES}
    PARENT_SCOPE)
