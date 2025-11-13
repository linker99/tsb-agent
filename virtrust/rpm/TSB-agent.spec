Name:           TSB-agent
Version:        1.0.0
Release:        1
Summary:        Trusted Software Base Agent for openEuler
Summary(zh_CN): 可信基础软件代理（TSB-agent）
License:        MulanPSL-2.0
URL:            https://gitee.com/openeuler/TSB-agent
Source0:        %{name}-%{version}.tar.gz
Source1:        googletest-v1.15.2.tar.gz
Source2:        openssl-3.3.2.tar.gz
Source3:        rapidjson-v1.1.0.tar.gz
Source4:        spdlog-v1.14.1.tar.gz
Source5:        libboundscheck.tar.gz

BuildRequires:  gcc, make
BuildRequires:  gcc-c++ >= 7, cmake >= 3.14
# Optional devel-time dependencies if using system libraries
#BuildRequires:  rapidjson-devel, spdlog-devel, gtest-devel, libboundscheck-devel

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

# 将依赖包解压到 CMake 期望的目录：build/deps/src
# 注意目录命名需与 cmake/deps/*.cmake 中 ExternalProject 名称一致
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

%global root_dir    %{_builddir}/%{name}-%{version}
%global build_dir   %{_builddir}/%{name}-%{version}/build
%global lib_out_dir %{build_dir}/lib64
%global bin_out_dir %{build_dir}/bin

%build
export CFLAGS="%{optflags}"
export CXXFLAGS="%{optflags}"

cmake -S . -B build \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo  \
    -DCMAKE_CXX_STANDARD=17 \
    -DCMAKE_CXX_STANDARD_REQUIRED=ON \
    -DENABLE_DOWNLOAD_DEPS=Off \
    -DCMAKE_LIBRARY_OUTPUT_DIRECTORY=%{lib_out_dir} \
    -DCMAKE_RUNTIME_OUTPUT_DIRECTORY=%{bin_out_dir}

cmake --build build -- -j%{?_smp_build_ncpus}

%install
rm -rf %{buildroot}
install -d -m 750 %{buildroot}%{_libdir}
install -d -m 750 %{buildroot}%{_bindir}
install -d -m 750 %{buildroot}%{_includedir}/%{name}
install -d -m 750 %{buildroot}%{_sysconfdir}/%{name}
install -d -m 750 %{buildroot}%{_localstatedir}/log/%{name}

# 库文件
install -m 550 %{lib_out_dir}/libvirtrust-shared.so      %{buildroot}%{_libdir}

# 可执行文件
install -m 550 %{bin_out_dir}/virtrust-sh                %{buildroot}%{_bindir}
install -m 550 %{bin_out_dir}/libvirtrustd               %{buildroot}%{_bindir}

# 配置文件
install -pm 644 %{root_dir}/test/data/config.json      %{_sysconfdir}/virtrust/config.json

# 头文件（如果项目有 include/）
if [ -d include ]; then
    cp -a include/* %{buildroot}%{_includedir}/%{name}/
fi

%files
%dir %attr(0750, root, root) %{_sysconfdir}/virtrust/
%config %attr(0640, root, root) %{_sysconfdir}/virtrust/config.json

%{_libdir}/libvirtrust-shared.so
%{_bindir}/virtrust-sh
%{_bindir}/libvirtrustd


%post
/sbin/ldconfig

%changelog
