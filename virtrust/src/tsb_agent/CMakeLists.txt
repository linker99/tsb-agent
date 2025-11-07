# Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

# mock
if(USE_MOCK_TSB_AGENT)
  add_subdirectory(mock)
else()
  add_library(tsb-agent INTERFACE)
  target_link_directories(tsb-agent INTERFACE ${CMAKE_DEPS_LIBDIR})
  target_link_libraries(tsb-agent
                        INTERFACE tsb-agent${CMAKE_SHARED_LIBRARY_SUFFIX})
endif()

# NOTE Make sure targets are linekd to tsb-agent
target_link_libraries(virtrust-obj PRIVATE tsb-agent)
target_link_libraries(virtrust-shared PRIVATE tsb-agent)
