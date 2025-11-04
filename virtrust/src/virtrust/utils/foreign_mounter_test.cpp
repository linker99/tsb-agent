/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include <filesystem>
#include <fstream>

#include "gtest/gtest.h"

#include "virtrust/utils/foreign_mounter.h"
#include "virtrust/utils/file_io.h"

namespace virtrust::test {

namespace {
  constexpr std::string_view IMAGE_PATH = "/data/openEuler-24.03-LTS-SP1-aarch64.gcow2";
  constexpr std::string_view VM_FILE_PATH = "/root/vnTestFile.txt";
  constexpr std::string_view VM_FILE_CONTENT = "This is a file in VM.\n";
}

namespace {
constexpr std::string_view TEST_INITRD_PATH = "/boot/initramfs-6.6.0-72.0.0.76.oe2403sp1.aarch64.img";
constexpr std::string_view TEST_LINUZ_PATH = "/boot/vmlinuz-6.6.0-72.0.0.76.oe2403sp1.aarch64";
std::string GetTestFilePath()
{
  auto filePath = std::filesystem::path(__FILE__);
  return (filePath / ".." / ".." / ".." / ".." / "test" / "data" / "grub.cfg").lexically_normal().string();
}
} // namespace

TEST(VerifyConfig, Works)
{
  std::string filePath(GetTestFilePath());
  FileInputStream fis (filePath);

  VerifyConfig config;
  config.ParseGrubCfgContent(fis.ReadAll());

  EXPECT_EQ(config.GetInitrdPath(), TEST_INITRD_PATH);

  EXPECT_EQ(config.GetLinuzPath(), TEST_LINUZ_PATH);
}

TEST(DISABLED_ForeignMounterTest, Works)
{
  auto mounter = ForeignMounter();
  EXPECT_TRUE(mounter.CheckOK());

  ForeignMounterRc rc;

  rc = mounter.EnableStrErrTrace();
  EXPECT_EQ(rc, ForeignMounterRc::OK);

  rc = mounter.DisableStrErrTrace();
  EXPECT_EQ(rc, ForeignMounterRc::OK);
}

TEST(DISABLED_ForeignMounterTest, Mount)
{
  auto mounter = ForeignMounter();
  EXPECT_TRUE(mounter.CheckOK());

  ForeignMounterRc rc;

  rc = mounter.TryInit();
  EXPECT_EQ(rc, ForeignMounterRc::OK);

  rc = mounter.Mount(IMAGE_PATH);
  EXPECT_EQ(rc, ForeignMounterRc::OK);

  std::string content;
  mounter.ReadFile(VM_FILE_PATH, content);
  EXPECT_EQ(content, VM_FILE_CONTENT);

  rc = mounter.UnMount();
  EXPECT_EQ(rc, ForeignMounterRc::OK);
}
} // namespace virtrust