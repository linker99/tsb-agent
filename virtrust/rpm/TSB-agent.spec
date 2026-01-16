Name:           TSB-agent
Version:        0.0.1
Release:        1
Summary:        Trusted Software Base Agent for openEuler
Summary(zh_CN): 可信基础软件代理（TSB-agent）
License:        MulanPSL-2.0
URL:            https://gitcode.com/openeuler/TSB-agent
Source0:        %{name}-%{version}.tar.gz
Source1:        googletest-v1.15.2.tar.gz
Source2:        openssl-3.3.2.tar.gz
Source3:        rapidjson-v1.1.0.tar.gz
Source4:        spdlog-v1.14.1.tar.gz
Source5:        libboundscheck.tar.gz

BuildRequires:  gcc, make, libboundscheck
BuildRequires:  gcc-c++ >= 7, cmake >= 3.14, grpc, grpc-devel, grpc-plugins, protobuf-devel, protobuf-compiler

# Runtime Requires
Requires:       libvirt-devel, libxml2-devel, openssl-devel, libguestfs-devel

%global __requires_exclude libinterfac\.so

%description
TSB-agent (Trusted Software Base Agent) provides trusted computing
capabilities including integrity verification and a daemon/CLI for
virtualization scenarios on openEuler.

# define sub-package
%package devel
Summary:        Development files for %{name}
Requires:       %{name} = %{version}-%{release}
%description    devel
TSB-agent (Trusted Software Base Agent) provides trusted computing
capabilities including integrity verification and a daemon/CLI for
virtualization scenarios on openEuler.

%prep
%autosetup -n %{name}-%{version}

# Extract dependency packages to directories expected by CMake: build/deps/src
# Note: Directory names must match ExternalProject names in cmake/deps/*.cmake
#   - googletest
#   - openssl (BUILD_IN_SOURCE On)
#   - rapidjson
#   - spdlog
#   - libboundscheck-src
DEPS_SRC="%{build_dir}/deps/src"
mkdir -p "$DEPS_SRC"

mkdir -p "$DEPS_SRC/googletest"
tar -xzf %{SOURCE1} -C "$DEPS_SRC/googletest" --strip-components=1

mkdir -p "$DEPS_SRC/openssl"
tar -xzf %{SOURCE2} -C "$DEPS_SRC/openssl" --strip-components=1

mkdir -p "$DEPS_SRC/rapidjson"
tar -xzf %{SOURCE3} -C "$DEPS_SRC/rapidjson" --strip-components=1

mkdir -p "$DEPS_SRC/spdlog"
tar -xzf %{SOURCE4} -C "$DEPS_SRC/spdlog" --strip-components=1

mkdir -p "$DEPS_SRC/libboundscheck-src"
tar -xzf %{SOURCE5} -C "$DEPS_SRC/libboundscheck-src" --strip-components=1

%global root_dir        %{_builddir}/%{name}-%{version}
%global build_dir       %{_builddir}/%{name}-%{version}/build
%global output_dir      %{_builddir}/%{name}-%{version}/output

%build
export CFLAGS="%{optflags}"
export CXXFLAGS="%{optflags}"

cmake -S . -B build \
    -DBUILD_TEST=Off \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo  \
    -DCMAKE_CXX_STANDARD=17 \
    -DCMAKE_CXX_STANDARD_REQUIRED=ON \
    -DENABLE_DOWNLOAD_DEPS=Off \
    -DCMAKE_INSTALL_PREFIX=%{output_dir}

cmake --build build -- -j%{?_smp_build_ncpus}

cmake --install build

%install
rm -rf %{buildroot}

# Directory
install -d -m 750 %{buildroot}%{_libdir}
install -d -m 750 %{buildroot}%{_bindir}
install -d -m 750 %{buildroot}%{_includedir}/virtrust
install -d -m 750 %{buildroot}%{_includedir}/virtrust/api
install -d -m 750 %{buildroot}%{_includedir}/virtrust/base
install -d -m 750 %{buildroot}%{_sysconfdir}/virtrust

# Library files
install -m 550 %{output_dir}/lib64/libvirtrust-shared.so        %{buildroot}%{_libdir}

# Executable files
install -m 550 %{output_dir}/bin/virtrust-sh                    %{buildroot}%{_bindir}
install -m 550 %{output_dir}/bin/libvirtrustd                   %{buildroot}%{_bindir}

# Header files
install -m 440 %{output_dir}/include/virtrust/api/*.h           %{buildroot}%{_includedir}/virtrust/api
install -m 440 %{output_dir}/include/virtrust/base/*.h          %{buildroot}%{_includedir}/virtrust/base

# Configuration files
install -pm 640 %{root_dir}/test/data/config.json               %{buildroot}%{_sysconfdir}/virtrust/config.json

%files
%dir %attr(0750, root, root) %{_sysconfdir}/virtrust/
%config %attr(0640, root, root) %{_sysconfdir}/virtrust/config.json

%{_libdir}/libvirtrust-shared.so
%{_bindir}/virtrust-sh
%{_bindir}/libvirtrustd
%{_includedir}/virtrust/api/*.h
%{_includedir}/virtrust/base/*.h

%post
/sbin/ldconfig

%changelog
