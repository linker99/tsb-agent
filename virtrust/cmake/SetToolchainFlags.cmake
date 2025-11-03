# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

include(CheckCXXCompilerFlag)
include(CheckCompilerFlag)
include(CheckLinkerFlag)

# CXX Compiler Flags
function(add_compiler_flags flag)
  string(FIND "${CMAKE_CXX_FLAGS}" "${flag}" flag_already_set)
  if(flag_already_set EQUAL -1)
    message(STATUS "Adding CXX compiler flag: ${flag} ...")
    check_cxx_compiler_flag("${flag}" flag_supported)
    if(flag_supported)
      set(CMAKE_CXX_FLAGS
          "${CMAKE_CXX_FLAGS} ${flag}"
          PARENT_SCOPE)
    endif()
    unset(flag_supported CACHE)
  endif()
endfunction()

# C Compiler Flags
function(add_c_compiler_flags flag)
  string(FIND "${CMAKE_CXX_FLAGS}" "${flag}" flag_already_set)
  if(flag_already_set EQUAL -1)
    message(STATUS "Adding C compiler flag: ${flag} ...")
    check_compiler_flag(C "${flag}" flag_supported)
    if(flag_supported)
      set(CMAKE_CXX_FLAGS
          "${CMAKE_CXX_FLAGS} ${flag}"
          PARENT_SCOPE)
    endif()
    unset(flag_supported CACHE)
  endif()
endfunction()

# Linker Flags
function(add_linker_flags flag)
  get_property(
    virtrust_link_options
    DIRECTORY
    PROPERTY LINK_OPTIONS)
  string(FIND "${virtrust_link_options}" "${flag}" flag_already_set)
  if(flag_already_set EQUAL -1)
    message(STATUS "Adding linker flag: ${flag} ...")
    check_linker_flag(CXX "${flag}" flag_supported)
    if(flag_supported)
      add_link_options(${flag})
    endif()
    unset(flag_supported CACHE)
  endif()
endfunction()

# Setup Toolchain

macro(set_toolchain_flags)

  # do no add runtime path information
  set(CMAKE_SKIP_RPATH TRUE)

  # all warnings are treated as errors
  add_compiler_flags(-Wall)
  add_compiler_flags(-Wextra)
  add_compiler_flags(-Werror)

  # compiler flags
  add_compiler_flags(-pipe)
  add_compiler_flags(-fno-common)
  add_compiler_flags(-fstrong-eval-order)
  add_compiler_flags(-fms-extensions)
  add_compiler_flags(-fno-strict-aliasing)
  add_compiler_flags(-freg-struct-return)

  # REVIEW additional warnnings
  add_compiler_flags(-Winvalid-pch)
  add_compiler_flags(-Wunused)
  add_compiler_flags(-Wunused-variable)
  add_compiler_flags(-Wunused-value)
  add_compiler_flags(-Wcast-align)
  add_compiler_flags(-Wcast-equal)
  add_compiler_flags(-Wwrite-strings)
  add_compiler_flags(-Wdata-time)
  add_compiler_flags(-Wstrict-prototypes)
  add_compiler_flags(-Wdelete-non-virtual-dtor)
  add_compiler_flags(-Wtrampolines)
  add_compiler_flags(-Woverloaded-virtual)

  # common linker flags (good-to-have)
  add_linker_flags(-Wl, -Bsymbolic)
  add_linker_flags(-rdynamic)
  add_linker_flags(-Wl, --no-undefined)

  #
  if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compiler_flags(-fstrack-protector-strong)
    add_compiler_flags(-fPIC)
    add_compiler_flags(-fPIE)
    add_compiler_flags(-D_FORTIRY_SOURCE=2)
    add_compiler_flags(-O2)
    add_compiler_flags(-ftrapv)

    add_linker_flags(-pie)
    add_linker_flags(-s)
    add_linker_flags(-Wl,-z,relro,-z,now)
    add_linker_flags(-Wl,-z,noexecstack)
  elseif(CMAKE_BUILD_TYPE STREQUAL "DEBUG")
    add_compiler_flags(-g)
  elseif(CMAKE_BUILD_TYPE STREQUAL "Coverage")
    add_compiler_flags(-g)

    # HACK it's strange that check_cxx_compiler_flags() function fail to add
    # --coverage flag, so we add this manually
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-arcs")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ftest-coverage")

    # NOTE the following liner flags only work on executables, which does not
    # get included in general linker flags
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lgcov")
  elseif(CMAKE_BUILD_TYPE STREQUAL "Asan")
    add_compiler_flags(-g)

    # https://cmake.org/pipermail/cmake/2019-October/070180.html
    set(_saved_CRT ${CMAKE_REQUIRED_LIBRARIES})
    set(CMAKE_REQUIRED_LIBRARIES "-fsanitize=address;asan")

    add_compiler_flags(-fsanitize=address)
    add_compiler_flags(-fsanitize=leak)
    add_compiler_flags(-fsanitize=undefined)
    add_compiler_flags(-fsanitize=pointer-compare)
    add_compiler_flags(-fsanitize=pointer-subtract)

    add_linker_flags(-fno-pie)
    add_linker_flags(-fsanitize=address)
    add_linker_flags(-fsanitize=leak)
    add_linker_flags(-fsanitize=undefined)
    add_linker_flags(-fsanitize=pointer-compare)
    add_linker_flags(-fsanitize=pointer-subtract)

    set(CMAKE_REQUIRED_LIBRARIES ${_saved_CRT})
  elseif(CMAKE_BUILD_TYPE STREQUAL "Fuzz")
    # TODO
    add_compiler_flags(-g)
  endif()

endmacro()
