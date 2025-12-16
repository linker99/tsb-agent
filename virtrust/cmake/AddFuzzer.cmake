# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

# Add a libFuzzer target with sanitizer flags and test registration
# Usage: add_fuzzer(NAME [SOURCE_FILE])
# If SOURCE_FILE is not provided, defaults to NAME.cpp
macro(add_fuzzer NAME)
    # Parse optional arguments
    set(one_value_args SOURCE_FILE)
    cmake_parse_arguments(ADD_FUZZER "" "${one_value_args}" "" ${ARGN})

    # Set default source file if not provided
    if(NOT ADD_FUZZER_SOURCE_FILE)
        set(ADD_FUZZER_SOURCE_FILE "${NAME}.cpp")
    endif()

    # Create the fuzzer executable
    add_executable(${NAME} ${ADD_FUZZER_SOURCE_FILE})

    # Apply compiler and linker sanitizer flags
    target_compile_options(${NAME} PRIVATE
            -fsanitize=fuzzer,address,undefined
            -fprofile-instr-generate
            -fcoverage-mapping
            -g
    )

    target_link_options(${NAME} PRIVATE
            -fsanitize=fuzzer,address,undefined
            -fprofile-instr-generate
            -fcoverage-mapping
    )

    target_link_libraries(${NAME} PRIVATE virtrust-shared)

    target_include_directories(${NAME} PRIVATE ${CMAKE_DEPS_INCLUDEDIR}
            $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
    )

    # Add CTest smoke test if BUILD_TEST is enabled
    if(BUILD_TEST)
        include(CTest)
        add_test(NAME ${NAME}_smoke
                COMMAND ${NAME} -runs=1000)
    endif()
endmacro()