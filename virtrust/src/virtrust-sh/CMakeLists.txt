# Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

add_library(virtrust-sh-obj OBJECT)

set(VIRTRUST_SH_SOURCE_FILES "")

add_subdirectory(operator)

target_sources(virtrust-sh-obj PRIVATE ${VIRTRUST_SH_SOURCE_FILES})

target_include_directories(
  virtrust-sh-obj PRIVATE $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
                          ${CMAKE_DEPS_INCLUDEDIR})

target_link_libraries(virtrust-sh-obj PRIVATE virtrust-shared)

# ----------------
# Final Executable
# ----------------

add_executable(virtrust-sh ${CMAKE_CURRENT_LIST_DIR}/main.cpp)

target_include_directories(
  virtrust-sh PRIVATE $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
                      ${CMAKE_DEPS_INCLUDEDIR})

target_link_libraries(virtrust-sh PRIVATE virtrust-sh-obj virtrust-shared)

install(TARGETS virtrust-sh RUNTIME DESTINATION bin PERMISSIONS OWNER_READ
                                                                OWNER_EXECUTE)
