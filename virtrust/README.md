# TSB-agent/virtrust

A Trusted Security Boot (TSB) Agent that provides virtualized Trusted Computing Module (vTPCM) support for openEuler 24.03 LTS SP3. This project enables trusted computing virtualization capabilities with a focus on virtual machine domain management and trust measurement.

## Project Overview

TSB-agent/virtrust is a sophisticated trusted computing solution for virtualized environments that implements:

- **Virtualized Trusted Computing Module (vTPCM)** management
- **Trust Chain Validation** for complete boot chain measurement and verification
- **Secure VM Migration** with encrypted certificate verification
- **Security Policy Management** for configurable security controls
- **Domain Management** for virtual machine lifecycle operations

The project is particularly focused on Chinese cryptographic standards (SM3) and openEuler integration, providing a comprehensive security architecture for virtualized environments.

##  Architecture

### Core Components

```
TSB-agent/virtrust/
├── src/
│   ├── virtrust/                 # Main library implementation
│   │   ├── api/                  # Public API for domain management
│   │   │   ├── domain.cpp/h      # VM domain lifecycle operations
│   │   │   ├── context.cpp/h     # API context management
│   │   │   └── defines.h         # Public API definitions
│   │   ├── base/                 # Core utilities
│   │   │   ├── custom_logger.cpp/h    # High-performance logging
│   │   │   ├── exception.cpp/h        # Error handling framework
│   │   │   ├── str_utils.cpp/h        # String utilities
│   │   │   └── log_adapt.cpp/h        # Logging adaptation layer
│   │   ├── crypto/               # Cryptographic implementations
│   │   │   └── sm3.cpp/h         # Chinese cryptographic hash algorithm
│   │   ├── dllib/                # Dynamic library loading abstractions
│   │   │   ├── libvirt.h/cpp     # libvirt integration
│   │   │   ├── libguestfs.h/cpp  # Guest filesystem access
│   │   │   ├── libxml2.h/cpp     # XML processing
│   │   │   └── openssl.h/cpp     # Cryptographic operations
│   │   ├── utils/                # Additional utilities
│   │   │   ├── file_io.cpp/h     # File I/O operations
│   │   │   ├── virt_xml_parser.cpp/h # XML configuration parsing
│   │   │   ├── migrate_helper.cpp/h  # VM migration utilities
│   │   │   └── foreign_mounter.cpp/h # Foreign filesystem mounting
│   │   └── link/                 # Linking functionality
│   ├── virtrust-sh/              # Shell interface
│   │   ├── main.cpp              # CLI entry point
│   │   └── operator/             # Command operators
│   │       ├── op_create.cpp/h   # Domain creation
│   │       ├── op_destroy.cpp/h  # Domain destruction
│   │       ├── op_start.cpp/h    # Domain startup
│   │       ├── op_migrate.cpp/h  # Domain migration
│   │       └── op_list.cpp/h     # Domain listing
│   ├── libvirtrustd/             # Daemon library
│   └── mock/                     # TSB agent mock for testing
│       ├── tsb_agent_itf.h       # TSB agent interface
│       ├── tsb_agent_impl.cpp    # Mock implementation
│       └── tsb_agent_adaptor.cpp # Adaptation layer
├── cmake/                        # Build system
│   ├── deps/                     # Dependency management
│   │   ├── openssl.cmake         # OpenSSL 3.3.2 configuration
│   │   ├── spdlog.cmake          # Logging library
│   │   ├── gtest.cmake           # Unit testing framework
│   │   ├── rapidjson.cmake       # JSON parsing
│   │   └── libboundscheck.cmake  # Memory safety
│   ├── SetToolchainFlags.cmake   # Compiler configuration
│   ├── ImportLibs.cmake          # Library importing
│   └── AddVirtrustTestIf.cmake   # Test configuration
└── test/                         # Testing infrastructure
    ├── data/                     # Test data and configurations
    ├── client/                   # Client-side tests
    └── server/                   # Server-side tests
```

## External Dependencies
- **OpenSSL 3.3.2** - Cryptographic operations (built statically)
- **libboundscheck** - Memory safety and bounds checking
- **RapidJSON** - JSON parsing and generation
- **libvirt** - Virtualization API integration
- **libguestfs** - Guest filesystem access
- **libxml2** - XML processing

## Features

### Domain Management API
- **VM Lifecycle**: Create, start, stop, destroy, migrate, list virtual machine domains
- **Trust Measurement**: Boot chain validation and measurement verification
- **Security Policy**: Configurable security policies and controls
- **Resource Management**: Memory, CPU, and storage resource allocation

### vTPCM Management
- **Virtual TPM**: Creation, startup, stop, and removal of virtual TPM instances
- **Trust Reporting**: Generation and verification of trust reports
- **Migration Support**: Secure migration of trusted VMs between hosts
- **Policy Control**: Security policy enforcement and management

### Command Line Interface
- **virtrust-sh**: Interactive shell for domain management operations
- **Operators**: Specialized commands for different operations
- **Batch Processing**: Support for scriptable operations

### Security Architecture
- **Trust Chain Validation**: BIOS → bootloader → kernel → TSB validation
- **Memory Safety**: Bounds checking and secure memory management
- **Cryptographic Security**: SM3 hash algorithm implementation
- **Secure Migration**: Encrypted VM migration with certificate verification

## Building from Source

### Prerequisites
- **openEuler 24.03 LTS SP3** or compatible Linux distribution
- **CMake 3.14.1+**
- **GCC 8+** or **Clang 10+** with C++17 support
- **Git**

### Build Commands

```bash
# Clone the repository
git clone https://gitee.com/jamie-cui/TSB-agent.git
cd TSB-agent/virtrust

# Configure build (Release mode with tests)
cmake -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTING=ON

# Build all components
cmake --build build -- -j$(nproc)

# Run tests
cd build
ctest --output-on-failure

# Install (optional)
sudo cmake --install build
```

### Build Options

| Option | Description | Default |
|--------|-------------|---------|
| `CMAKE_BUILD_TYPE` | Build configuration (Debug/Release/RelWithDebInfo) | Release |
| `ENABLE_TESTING` | Enable unit tests | ON |
| `ENABLE_COVERAGE` | Enable code coverage reporting | OFF |

### Memory Safety

The project includes comprehensive bounds checking:

```bash
# Build with libboundscheck
cmake -B build -DENABLE_BOUNDS_CHECK=ON
cmake --build build

# Run with bounds checking
LD_LIBRARY_PATH=/path/to/libboundscheck ./build/bin/virtrust-sh
```

## Testing

### Unit Tests
```bash
# Run all tests
cd build
ctest

# Run specific test suite
./bin/custom_logger_test
./bin/domain_test
./bin/sm3_test
```

### Coverage Report
```bash
# Enable coverage
cmake -B build -DENABLE_COVERAGE=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest

# Generate coverage report
lcov --capture --directory build --output-file coverage.info
genhtml coverage.info --output-directory coverage_report
```

### Code Formatting
```bash
# Format all source code
./format-all.sh

# Or use clang-format directly
find src -name "*.cpp" -o -name "*.h" | xargs clang-format -i
```

## Security Considerations

### Trust Chain Validation
The system implements complete trust chain validation:
1. **BIOS/UEFI** measurements
2. **Bootloader** integrity verification
3. **Kernel** module verification
4. **TSB Agent** validation
5. **Application** layer measurements

### Memory Safety
- Comprehensive bounds checking with libboundscheck
- Secure memory allocation and deallocation
- Protection against buffer overflows and memory corruption
- Automatic memory leak detection in debug builds

### Cryptographic Security
- SM3 hash algorithm implementation for Chinese cryptographic standards
- Certificate-based authentication for migration
- Encrypted communication channels
- Secure key storage and management

## Contributing

### Development Workflow
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes with proper tests
4. Ensure code formatting (`./format-all.sh`)
5. Run tests (`ctest --output-on-failure`)
6. Submit a pull request

### Code Style
- Follow Google C++ Style Guide
- Use clang-format for consistent formatting
- Include comprehensive unit tests
- Document public APIs with Doxygen
- Use meaningful commit messages

### Testing Requirements
- All new features must include unit tests
- Maintain code coverage above 80%
- Test both positive and negative scenarios
- Include integration tests for complex workflows


---

**Note**: This project is specifically designed for openEuler 24.03 LTS SP3 and implements Chinese cryptographic standards for trusted computing in virtualized environments.
