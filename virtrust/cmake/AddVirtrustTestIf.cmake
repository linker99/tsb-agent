# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

macro(add_virtrust_test_if NAME)
  if(BUILD_TEST)
    add_executable(${NAME} ${NAME}.cpp)
    target_link_libraries(${NAME} PRIVATE virtrust-shared Deps::gtest)
    add_test(NAME ${NAME} COMMAND ${NAME})
    target_include_directories(
      ${NAME} PRIVATE $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
                      ${CMAKE_DEPS_INCLUDEDIR})
    set_tests_properties(
      ${NAME}
      PROPERTIES
        ENVIRONMENT
        "LD_LIBRARY_PATH:${CMAKE_LIBRARY_OUTPUT_DIRECTORY}:$ENV{LD_LIBRARY_PATH}"
    )
  endif()
endmacro()

macro(add_virtrust_sh_test_if NAME)
  if(BUILD_TEST)
    add_executable(${NAME} ${NAME}.cpp)
    target_link_libraries(${NAME} PRIVATE virtrust-sh-obj virtrust-shared
                                          Deps::gtest)
    add_test(NAME ${NAME} COMMAND ${NAME})
    target_include_directories(
      ${NAME} PRIVATE $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
                      ${CMAKE_DEPS_INCLUDEDIR})
    set_tests_properties(
      ${NAME}
      PROPERTIES
        ENVIRONMENT
        "LD_LIBRARY_PATH:${CMAKE_LIBRARY_OUTPUT_DIRECTORY}:$ENV{LD_LIBRARY_PATH}"
    )
  endif()
endmacro()

macro(add_libvirtrustd_test_if NAME)
  if(BUILD_TEST)
    add_executable(${NAME} ${NAME}.cpp)
    target_link_libraries(${NAME} PRIVATE libvirtrustd-obj virtrust-shared
                                          Deps::gtest)
    add_test(NAME ${NAME} COMMAND ${NAME})
    target_include_directories(
      ${NAME} PRIVATE $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
                      ${CMAKE_DEPS_INCLUDEDIR})
    set_tests_properties(
      ${NAME}
      PROPERTIES
        ENVIRONMENT
        "LD_LIBRARY_PATH:${CMAKE_LIBRARY_OUTPUT_DIRECTORY}:$ENV{LD_LIBRARY_PATH}"
    )
  endif()
endmacro()
