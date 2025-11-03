// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include "virtrust/api/context.h"
#include "virtrust/api/defines.h"

namespace virtrust {
/**
 * 创建虚拟机
 * @param conn 连接参数
 * @param args 参数 参考virt-install --help
 * 名称字段必须指定。arg[0]为virt-install的路径 如：、usr/bin/virt-install
 * --allow-store-measurements可选 是否鞥新tsb的度量值
 * @return VirtrustRc
 */
VirtrustRc DomainCreate(const std::unique_ptr<ConnCtx> &conn,
                        const std::vector<std::string> &args);

/**
 * 停止虚拟机
 * @param conn 连接参数
 * @param flags 见DomainDestroyFlags中的选项
 * @param domainName 虚拟机名称，isOnlyTsb为true时只更新tsb相关资源
 * 为虚拟机UUID，当isOnlyTsb为true时将忽略flags入参
 * @param isOnlyTsb 是否只更新tsb资源，为true时只更新tsb资源
 * @return VirtrustRc
 */
VirtrustRc DomainDestroy(const std::unique_ptr<ConnCtx> &conn,
                         const std::string &domainName, unsigned int flags,
                         bool isOnlyTsb = false);

VirtrustRc DomainMigrate(const std::unique_ptr<ConnCtx> &conn,
                         const std::string &domainName,
                         const std::string &destUri);

/**
 * 启动虚拟机
 * @param conn 连接参数
 * @param flags 见DomainStartFlags中的选项
 * @param domainName 虚拟机名称，isOnlyTsb为true时只更新tsb相关资源
 * 为虚拟机UUID，当isOnlyTsb为true时将忽略flags入参
 * @param isOnlyTsb 是否只更新tsb资源，为true时只更新tsb资源
 * @return VirtrustRc
 */
VirtrustRc DomainStart(const std::unique_ptr<ConnCtx> &conn,
                       const std::string &domainName, unsigned int flags,
                       bool isOnlyTsb = false);

/**
 * 删除虚拟机
 * @param conn 连接参数
 * @param flags
 * 见DomainUndefineFlags,DOMAIN_UNDEFINE_NVRAM和DOMAIN_UNDEFINE_KEEP_NVRAM仅支持同一时间指定一种
 * @param domainName 虚拟机名称，isOnlyTsb为true时只更新tsb相关资源
 * 为虚拟机UUID，当isOnlyTsb为true时将忽略flags入参
 * @param isOnlyTsb 是否只删除tsb资源，为true时只删除tsb资源
 * @return VirtrustRc
 */
VirtrustRc DomainUndefine(const std::unique_ptr<ConnCtx> &conn,
                          const std::string &domainName, unsigned int flags,
                          bool isOnlyTsb = false);

/**
 * 展示虚拟机
 * @param conn 连接参数
 * @param flags
 * 见DomainListFlag选项，可组合LIST_DOMAINS_ACTIVE|LIST_DOMAINS_INACTIVE
 * @param dmoainInfos 查询到的虚拟机信息
 * @param printErrToCli
 * 是否屏显tsb资源和libvirt资源不一致的错误信息，如果libvirt有但是tsb没有不会屏显，日志会有warn日志
 * @return VirtrustRc
 */
VirtrustRc DomainList(const std::unique_ptr<ConnCtx> &conn, unsigned int flags,
                      std::unordered_map<std::string, DomainInfo> &domainInfos,
                      bool printErrToCli = false);
} // namespace virtrust
