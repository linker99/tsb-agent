# Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

# tsb_agent
add_subdirectory(tsb_agent)

# api
add_subdirectory(virtrust)

if(NOT CMAKE_BUILD_TYPE STREQUAL "Fuzz")
    # cli
    add_subdirectory(virtrust-sh)
    # daemon
    add_subdirectory(libvirtrustd)
else()
    message(STATUS "Fuzz Mode: Skipping production executables (virtrust-sh, libvirtrustd).")
endif()
