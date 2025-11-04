/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#include <string>

#include "virtrust/base/logger.h"
#include "virtrust/dllib/libxml2.h"
#include "virtrust/utils/foreign_mounter.h"

namespace virtrust {

using NodeConditionMatchFunc = std::function<bool(const xmlNodePtr)>;

class VirtXmlParser {
public:
  VirtXmlParser() = default;

  ~VirtXmlParser() {
    if (doc_ != nullptr) {
      libxml2_.xmlFreeDoc(doc_);
    }
  }

  std::vector<xmlNodePtr> FindNodesByPath(std::string_view absPath);

  // Load the VM xml file, the function reloads the file each time it is called.
  bool LoadFile(std::string_view filename);

  std::string GetVmName();

  std::string GetDiskPath();

  std::string GetLoaderPath();

  VerifyConfig Parse(const std::string &filePath);

private:
  Libxml2 &libxml2_ = Libxml2::GetInstance();
  xmlDocPtr doc_ = nullptr;

  void SearchCurrLevel(std::vector<xmlNodePtr> &currLevel,
                       std::vector<xmlNodePtr> &nextLevel,
                       const std::string &nodeName);
};

} // namespace virtrust