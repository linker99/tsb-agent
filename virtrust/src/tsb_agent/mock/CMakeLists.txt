# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

# Note mock/tsb-agent is a sepatate static lib

add_library(tsb-agent OBJECT ${CMAKE_CURRENT_LIST_DIR}/tsb_agent_impl.cpp
                             ${CMAKE_CURRENT_LIST_DIR}/tsb_agent_adaptor.cpp)

target_include_directories(
  tsb-agent PRIVATE ${CMAKE_DEPS_INCLUDEDIR}
                    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>)

target_link_libraries(tsb-agent PRIVATE Deps::spdlog Deps::secure_c)

# add mock tsb-agent test

if(BUILD_TEST)
  add_executable(tsb_agent_test tsb_agent_test.cpp)
  target_link_libraries(tsb_agent_test PRIVATE tsb-agent Deps::gtest)
  target_include_directories(
    tsb_agent_test PRIVATE ${CMAKE_DEPS_INCLUDEDIR}
                           $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>)

  add_test(NAME tsb_agent_test COMMAND tsb_agent_test)
  set_tests_properties(
    tsb_agent_test
    PROPERTIES
      ENVIRONMENT
      "LD_LIBRARY_PATH=${CMAKE_LIBRARY_OUTPUT_DIRECTORY}:$ENV{LD_LIBRARY_PATH}")

  add_executable(tsb_agent_impl_test tsb_agent_impl_test.cpp)
  target_link_libraries(tsb_agent_impl_test PRIVATE tsb-agent Deps::gtest)
  target_include_directories(
    tsb_agent_impl_test PRIVATE ${CMAKE_DEPS_INCLUDEDIR}
                                $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>)

  add_test(NAME tsb_agent_impl_test COMMAND tsb_agent_impl_test)
  set_tests_properties(
    tsb_agent_impl_test
    PROPERTIES
      ENVIRONMENT
      "LD_LIBRARY_PATH=${CMAKE_LIBRARY_OUTPUT_DIRECTORY}:$ENV{LD_LIBRARY_PATH}")

endif()
