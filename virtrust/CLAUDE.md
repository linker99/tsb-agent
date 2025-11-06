# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the **virtrust** project - a TSB (Trusted Security Boot) Agent for virtualized Trusted Computing Module (vTPCM) support on openEuler 24.03 LTS SP3. The project provides trusted computing virtualization capabilities with focus on virtual machine domain management and trust measurement.

## Build System

This project uses CMake with a custom dependency management system.

### Build Commands

```bash
# Configure build (Release build by default)
mkdir build && cd build
cmake ..

# Configure with specific build type
cmake -DCMAKE_BUILD_TYPE=Debug ..
cmake -DCMAKE_BUILD_TYPE=Coverage ..
cmake -DCMAKE_BUILD_TYPE=Asan ..

# Configure options
cmake -DBUILD_TEST=On ..          # Enable tests (default: On)
cmake -DUSE_MOCK_TSB_AGENT=On .. # Use mock TSB agent (default: On, DO NOT USE IN PRODUCTION)

# Build
cmake --build .

# Run all tests
ctest --output-on-failure

# Run single test (after build)
./build/bin/custom_logger_test

# Format code
./format-all.sh

# Generate coverage report (when built with Coverage type)
make coverage

# Build script alternative
./build.sh                    # Build with Release configuration
./build.sh cicd_default      # Same as above
```

### Key Build Targets

- `virtrust-shared` - Main shared library
- `virtrust-obj` - Object library containing all components
- `mock-tsb-agent` - Mock TSB agent implementation for testing

## Project Structure

### Core Components

- **src/virtrust/** - Main library implementation
  - `api/` - Public API including domain management (`domain.cpp`, `context.cpp`)
  - `base/` - Core utilities (logging, exceptions, string utils)
  - `crypto/` - Cryptographic implementations (SM3 hash)
  - `dllib/` - Dynamic library loading
  - `link/` - Linking functionality
  - `utils/` - Additional utilities

- **src/mock/** - Mock TSB agent implementation
  - `tsb_agent_itf.h` - TSB agent interface definitions
  - `tsb_agent_impl.cpp` - Mock implementation
  - `tsb_agent_adaptor.cpp` - Adaptation layer

- **src/virtrust-sh/** - Shell interface components
- **src/libvirtrustd/** - Daemon library components

### Testing Infrastructure

Tests are co-located with source files (e.g., `domain_test.cpp` alongside `domain.cpp`). The project uses custom CMake macros for test creation:

- `add_virtrust_test_if()` - For standard library tests
- `add_virtrust_sh_test_if()` - For shell interface tests
- `add_libvirtrustd_test_if()` - For daemon library tests

### Dependencies

Dependencies are managed through the CMake deps system in `cmake/deps/`:
- OpenSSL (crypto)
- libboundscheck (security)
- spdlog (logging)
- gtest (testing)
- rapidjson (JSON parsing)

Dependencies are automatically downloaded and built as part of the CMake configuration process.

## Key APIs and Concepts

### Domain Management
The project provides virtual domain lifecycle management through the API in `src/virtrust/api/`:
- Domain creation, start, stop, destroy operations
- Domain listing with filtering (active/inactive)
- Trust measurement and verification for VMs

### TSB Agent Interface
The TSB agent interface (`src/mock/tsb_agent_itf.h`) defines:
- Virtual TPM (vTPCM) management functions
- Trust measurement and reporting
- Migration support for trusted VMs
- Security policy management

### Security Architecture
- SM3 cryptographic hash implementation
- Trust chain validation (BIOS → bootloader → kernel → TSB)
- Memory safety through bounds checking
- Secure logging and exception handling

## Development Notes

- **Mock vs Production**: Default build uses `USE_MOCK_TSB_AGENT=On` for development. Production builds must set this to Off.
- **Memory Management**: TSB agent interface uses malloc/free - remember to free allocated memory.
- **Error Handling**: Comprehensive error codes defined in `tsb_agent_itf.h` and `api/defines.h`.
- **Logging**: Custom logging adaptation in `base/` with spdlog backend.
- **Standards**: C17 and C++17 standards are enforced.

## Testing

Tests use gtest framework and can be run with `ctest`. The build automatically sets up proper library paths for test execution using environment variables.

### Test Structure
- Tests are co-located with source files (e.g., `domain_test.cpp` alongside `domain.cpp`)
- Individual test executables are built in `build/bin/` directory
- Test certificates are auto-generated during build using OpenSSL

### Running Tests
```bash
# Run all tests
ctest --output-on-failure

# Run specific test
./build/bin/custom_logger_test
./build/bin/domain_test
```

Coverage reporting is available with `cmake -DCMAKE_BUILD_TYPE=Coverage` and `make coverage`.

## Code Formatting

The project includes automated code formatting:
- `./format-all.sh` - Formats C++ and CMake files using clang-format and cmake-format
- `.clang-format` configuration defines code style rules