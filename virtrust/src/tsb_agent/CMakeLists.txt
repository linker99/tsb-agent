# Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

# mock
if(USE_MOCK_TSB_AGENT)
  add_subdirectory(mock)
else()
  add_library(tsb-agent INTERFACE)
  file(COPY /root/libinterfac.so DESTINATION ${CMAKE_DEPS_LIBDIR})
  target_link_directories(tsb-agent INTERFACE ${CMAKE_DEPS_LIBDIR})
  target_link_libraries(tsb-agent INTERFACE libinterfac.so)
endif()

# NOTE Make sure targets are linekd to tsb-agent
target_link_libraries(virtrust-obj PRIVATE tsb-agent)
target_link_libraries(virtrust-shared PRIVATE tsb-agent)
target_link_libraries(virtrust-sh PRIVATE tsb-agent)
target_link_libraries(libvirtrustd PRIVATE tsb-agent)
