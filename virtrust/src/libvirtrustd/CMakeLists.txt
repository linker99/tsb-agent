# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

# executable
add_executable(libvirtrustd ${CMAKE_CURRENT_LIST_DIR}/main.cpp
                            ${CMAKE_CURRENT_LIST_DIR}/utils.cpp)

target_include_directories(
  libvirtrustd PRIVATE ${CMAKE_DEPS_INCLUDEDIR}
                       $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>)

target_link_libraries(libvirtrustd PRIVATE virtrust-shared Deps::rapidjson)
