cmake_minimum_required(VERSION 3.22)
project(virtrust CXX C)

option(BUILD_TEST "Enable/Disable tests" On)
option(USE_MOCK_TSB_AGENT "Use Mocked Tsb Agent (DO NOT USE IN PRODUCTION)" On)

set(USER_DEPS_DIR
    "${PROJECT_SOURCE_DIR}/external"
    CACHE
      STRING
      "Pre-Build Dependency Directory, default to ${PROJECT_SOURCE_DIR}/external"
)

if(NOT BUILD_TEST AND CMAKE_BUILD_TYPE STREQUAL "Asan")
  message(
    WARNING
      "CMAKE_BUILD_TYPE is Asan but BUILD_TEST has been set to Off, turn on BUILD_TEST automatically."
  )
  set(BUILD_TEST On)
endif()

if(NOT BUILD_TEST AND CMAKE_BUILD_TYPE STREQUAL "Coverage")
  message(
    WARNING
      "CMAKE_BUILD_TYPE is Coverage but BUILD_TEST has been set to Off, turn on BUILD_TEST automatically."
  )
  set(BUILD_TEST On)
endif()

if(NOT BUILD_TEST AND CMAKE_BUILD_TYPE STREQUAL "Fuzz")
  message(
    WARNING
      "CMAKE_BUILD_TYPE is Fuzz but BUILD_TEST has been set to Off, turn on BUILD_TEST automatically."
  )
  set(BUILD_TEST On)
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE
      "Release"
      CACHE
        STRING
        "Choose the type of build, e.g. Debug, Release, Coverage, Asan, Fuzz"
        FORCE)
  message(
    WARNING
      "CMAKE_BUILD_TYPE not specified, defaulting to '${CMAKE_BUILD_TYPE}'")
endif()

if(USE_MOCK_TSB_AGENT)
  add_compile_definitions(USE_MOCK_TSB_AGENT)
  if(CMAKE_BUILD_TYPE STREQUAL "Release")
    message(
      WARNING
        "USE_MOCK_TSB_AGENT has been set to On while building with Release, please make sure this is intentional."
    )
  endif()
endif()

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set_property(CACHE CMAKE_INSTALL_PREFIX PROPERTY VALUE ${PROJECT_BINARY_DIR})
  message(
    WARNING
      "CMAKE_INSTALL_PREFIX not specified, defaulting to '${PROJECT_BINARY_DIR}'"
  )
endif()

cmake_policy(GET CMP0097 NEW)

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/")
set(CMAKE_EXPORT_COMPILE_COMMANDS On)

include(GNUInstallDirs)

set(DEPS_INSTALL_PREFIX_NAME deps)
set(CMAKE_DEPS_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/${DEPS_INSTALL_PREFIX_NAME})
set(CMAKE_DEPS_INCLUDEDIR
    ${CMAKE_DEPS_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR})
set(CMAKE_DEPS_LIBDIR ${CMAKE_DEPS_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})

# Explicitly create build/deps directory
file(MAKE_DIRECTORY ${CMAKE_DEPS_LIBDIR})
file(MAKE_DIRECTORY ${CMAKE_DEPS_INCLUDEDIR})
file(MAKE_DIRECTORY ${CMAKE_DEPS_SRCDIR})

set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 17)

set(CMAKE_POSITION_INDEPENDENT_CODE On)

set(CMAKE_CXX_FLAGS_RELEASE "")
set(CMAKE_CXX_FLAGS_DEBUG "")

include(SetToolchainFlags)
set_toolchain_flags()

# HACK compiler flags, try remove this in the future
add_compiler_flags(-Wno-missing-field-initializers) # for dllib guestfs
add_compiler_flags(-Wno-unused-parameter) # for tsb interface
add_compiler_flags(-Wno-deprecated-declarations) # rapidjson headers
add_compiler_flags(-Wno-error=pragmas) # rapidjson headers
add_compiler_flags(-Wno-class-memaccess) # rapidjson headers
add_compiler_flags(-Wno-implicit-fallthrough) # rapidjson headers
add_compiler_flags(-Wno-template-body) # rapidjson headers

get_property(
  virtrust_link_options
  DIRECTORY
  PROPERTY LINK_OPTIONS)

message(STATUS "=============================================================")
message(STATUS "User Options and Configurations")
message(STATUS "=============================================================")
message(STATUS "CMake Version    :${CMAKE_VERSION}")
message(STATUS "Build Type    :${CMAKE_BUILD_TYPE}")
message(STATUS "CPU Type    :${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "Compiler   :${CMAKE_CXX_COMPILER_ID}")
message(STATUS "Compiler Version  :${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "C Standard  :${CMAKE_C_STANDARD}")
message(STATUS "C++ Standard  :${CMAKE_CXX_STANDARD}")
message(STATUS "Compiler Flags  :\n${CMAKE_CXX_FLAGS}")
message(STATUS "Linker Flags  :\n${virtrust_link_options}")
message(STATUS "Exe Linker Flags  :\n${CMAKE_EXE_LINKER_FLAGS}")
message(STATUS "CMAKE_INSTALL_PREFIX  :${CMAKE_INSTALL_PREFIX}")
message(STATUS "CMAKE_DEPS_SRCDIR  :${CMAKE_DEPS_SRCDIR}")
message(STATUS "(opt) BUILD_TEST  :${BUILD_TEST}")
message(STATUS "(opt) USE_MOCK_TSB_AGENT  :${USE_MOCK_TSB_AGENT}")

include(FetchContent)
include(ExternalProject)

set(FETCHCONTENT_BASE_DIR ${CMAKE_DEPS_INSTALL_PREFIX}/src)

include(ImportLibs)
include(deps/openssl)
include(deps/libboundscheck)
include(deps/spdlog)
include(deps/gtest)
include(deps/rapidjson)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY
    ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY
    ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
set(CMAKE_INCLUDE_OUTPUT_DIRECTORY
    ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIRDIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY
    ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR})

include(AddVirtrustTestIf)

if(BUILD_TEST)
  include(CTest)
  enable_testing()
  list(APPEND CMAKE_CTEST_ARGUMENTS "--output-on-failure")
endif()

add_subdirectory(src)

if(BUILD_TEST)
  add_subdirectory(test)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Coverage")
  find_program(LCOV_PATH lcov)
  find_program(GENHTML_PATH genhtml)
  if(LCOV_PATH AND GENHTML_PATH)
    add_custom_target(
      coverage
      COMMAND
        ${LCOV_PATH} --capture --directory . --exclue "build/*" --exclude
        "external/*" --exclude "/usr/*" --output-file coverage.info
        --ignore-errors mismatch,inconsistent
      COMMAND ${GENHTML_PATH} coverage.info --output-directory
              ${CMAKE_BINARY_DIR}/coverage_report --ignore-errors inconsistent
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
      COMMENT "Generating code coverage report..."
      VERBATIM)
  else()
    add_custom_target(
      coverage
      COMMAND ${CMAKE_COMMAND} -E echo
              "lcov and/or genhtml not found. Generating gcov files instead."
      COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/gcov_report
      COMMAND find src -name "*.gcda" -exec gcov -pb {} +
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
      COMMENT "Generating gcov coverage report..."
      VERBATIM)
  endif()
endif()
