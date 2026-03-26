# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

macro(add_virtrust_test_if NAME)
  if(BUILD_TEST)
    add_executable(${NAME} ${NAME}.cpp)
    target_link_libraries(${NAME} PRIVATE virtrust-shared Deps::gtest)
    add_test(NAME ${NAME} COMMAND ${NAME})
    target_include_directories(
      ${NAME}
      PRIVATE $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
              ${CMAKE_BINARY_DIR}/src/virtrust # for protobuf
              ${CMAKE_BINARY_DIR}/src # for protobuf
              ${CMAKE_DEPS_INCLUDEDIR})
    set_tests_properties(
      ${NAME}
      PROPERTIES
        WORKING_DIRECTORY
        ${CMAKE_BINARY_DIR}
        ENVIRONMENT
        "LD_LIBRARY_PATH=${CMAKE_LIBRARY_OUTPUT_DIRECTORY}:${CMAKE_DEPS_LIBDIR}:$ENV{LD_LIBRARY_PATH}"
    )
    # Set RPATH for the test executable
    set_target_properties(
      ${NAME}
      PROPERTIES INSTALL_RPATH
                 "${CMAKE_LIBRARY_OUTPUT_DIRECTORY};${CMAKE_DEPS_LIBDIR}"
                 BUILD_WITH_INSTALL_RPATH TRUE)
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
        WORKING_DIRECTORY
        ${CMAKE_BINARY_DIR}
        ENVIRONMENT
        "LD_LIBRARY_PATH=${CMAKE_LIBRARY_OUTPUT_DIRECTORY}:${CMAKE_DEPS_LIBDIR}:$ENV{LD_LIBRARY_PATH}"
    )
    # Set RPATH for the test executable
    set_target_properties(
      ${NAME}
      PROPERTIES INSTALL_RPATH
                 "${CMAKE_LIBRARY_OUTPUT_DIRECTORY};${CMAKE_DEPS_LIBDIR}"
                 BUILD_WITH_INSTALL_RPATH TRUE)
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
        WORKING_DIRECTORY
        ${CMAKE_BINARY_DIR}
        ENVIRONMENT
        "LD_LIBRARY_PATH=${CMAKE_LIBRARY_OUTPUT_DIRECTORY}:${CMAKE_DEPS_LIBDIR}:$ENV{LD_LIBRARY_PATH}"
    )
    # Set RPATH for the test executable
    set_target_properties(
      ${NAME}
      PROPERTIES INSTALL_RPATH
                 "${CMAKE_LIBRARY_OUTPUT_DIRECTORY};${CMAKE_DEPS_LIBDIR}"
                 BUILD_WITH_INSTALL_RPATH TRUE)
  endif()
endmacro()
