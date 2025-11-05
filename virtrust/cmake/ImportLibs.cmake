# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

macro(import_static_lib_from LIBNAME LIB)
  add_library(${LIBNAME} STATIC IMPORTED)
  set_target_properties(
    ${LIBNAME}
    PROPERTIES IMPORTED_LOCATION
               ${CMAKE_DEPS_LIBDIR}/${LIBNAME}${CMAKE_STATIC_LIBRARY_SUFFIX})
  add_dependencies(${LIBNAME} ${LIB})
endmacro()

macro(import_shared_lib_from LIBNAME LIB)
  add_library(${LIBNAME} SHARED IMPORTED)
  set_target_properties(
    ${LIBNAME}
    PROPERTIES IMPORTED_LOCATION
               ${CMAKE_DEPS_LIBDIR}/${LIBNAME}${CMAKE_SHARED_LIBRARY_SUFFIX})
  add_dependencies(${LIBNAME} ${LIB})
endmacro()
