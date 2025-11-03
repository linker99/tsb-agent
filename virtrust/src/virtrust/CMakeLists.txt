# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

add_library(virtrust-obj OBJECT)

set(VIRTRUST_SOURCE_FILES "")

add_subdirectory(api)
add_subdirectory(base)
add_subdirectory(dllib)
add_subdirectory(crypto)
add_subdirectory(link)
add_subdirectory(utils)

# Object lib

target_sources(virtrust-obj PRIVATE ${VIRTRUST_SOURCE_FILES})

target_include_directories(
    virtrust-obj PRIVATE ${CMAKE_DEPENDENCY_INCLUDEDIR}
                         $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>)

target_link_libraries(virtrust-obj PRIVATE Deps::spdlog Deps::secure_c
                                           Deps::tsb_agent Deps::hcom)

# Shared lib

add_library(virtrust-shared SHARED $<TARGET_OBJECTS:virtrust-obj>)

target_include_directories(
    virtrust-shared PRIVATE ${CMAKE_DEPENDENCY_INCLUDEDIR}
                            $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>)

target_link_libraries(virtrust-shared PRIVATE Deps::spdlog Deps::secure_c
                                              Deps::tsb_agent Deps::hcom)