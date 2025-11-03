#!/bin/bash

#
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
#

###
### build.sh --- build project
### Usage:
###     build.sh <target> [-D] [-C] [-t <target>]
### Options:
###     <target>            Build target useby Make
###     -h, --help          show this help message and exit
###     -t || --target      Specifying build target, default is `all`
###                         Support targets:
###                             cicd_default: build default target


# 函数内命令（后台命令） 失败时退出脚本
#set -o errtrace
# 脚本内命令(前台命令)失败时，立即退出脚本
#set -o errexit


build_target='cicd_default'
build_type='Release'
build_asan='Off'
enable_test='On'

# 获取项目根目录(目前为构建脚本所在目录)
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}") " > /dev/null 2>&1 && pwd) "
OUTPUT_DIR=${PROJECT_ROOT}/output

# 日志打印辅助函数
function log_info() {
    if [ $# -lt 1 ]; then
        return
    fi

    echo "$(date +"%F %T") [INFO] $*" >> "$LOG_FILE"
    echo "$(date +"%F %T") [INFO] $*"
}

function help() {
    sed -rn 's/^### ?//;T;p;' "$0"
}

# 解析命令行参数
function parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
        -h | --help)
            help
            exit
            ;;
        -t | --target)
            if [[ $# -gt 1 && "$2" != "-"* ]]; then
                build_target="$2"
                shift 2
            else 
                log_info "Error: Argument required after -t||--target."
                exit 1
            fi
            ;;
        *)
            [ "$1" != ""] && build_target="$1"
            shift
            ;;
        esac
    done
}


function build_output() {
    cmake ..\
        -DCMAKE_BUILD_TYPE=$build_type \
        -DBUILD_TEST=${enable_test}\
        -DUSE_MOCK_TSB_AGENT=On \
        -DCMAKE_INSTALL_PREFIX=${OUTPUT_DIR}/virtrust \

    make -j$(CPU_NUM)
    make install
}

function build_cmake() {
    log_info "***** start build cmake *****"

    pushd build
    log_info "building target ${build_target}"
    if [[ "${build_target}" == "cicd_default" ]]; then
        build_type='Release'
        enable_test='Off'
        build_output
    fi

    local ret=$?
    if [[ $ret -ne 0 ]]; then
        log_info "***** build cmake failed *****"
        echo_failure
        exit 1
    fi
}

echo $(date +"%Y-%m-%d %H-%M"): "$0" "$@"
START_TIME=$(date +%s.%N)

PROJECT_BUILD_DIR=$PROJECT_ROOT_DIR/build
LOG_FILE=$PROJECT_BUILD_DIR/build.log

cd "${PROJECT_ROOT_DIR}"

[ ! -d "${PROJECT_BUILD_DIR}/build" ] && mkdir -p "${PROJECT_BUILD_DIR}/build"

parse_args "$@"
build_cmake

ENC_TIME=$(date +%s.%N)
EXEC_TIME=$(echo "scale=3;($ENC_TIME - $START_TIME)/1" | bc)
echo -e $(data +"%Y-%m-%d %H-%M)"): "\033[32m" build success in "${EXEC_TIME}"s '\033[0m' 