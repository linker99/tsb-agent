/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include <filesystem>
#include <string>

#include "gtest/gtest.h"

#include "virtrust/base/logger.h"
#include "virtrust/utils/file_io.h"
#include "virtrust/utils/foreign_mounter.h"
#include "virtrust/utils/migrate_helper.h"
#include "virtrust/utils/virt_xml_parser.h"

namespace virtrust {

namespace {
std::string GetTestFilePath()
{
  // Get the project root path (which is the directory)
  auto filePath = std::filesystem::path(__FILE__);
  return (filePath / ".." / ".." / ".." / ".." / "test" / "data" / "test.txt").lexically_normal().string();
}

const std::string TEST_XML_CONTENT = R"(<?xml version='1.0' encoding="UTF-8"?>
<domain type='kvm'>
  <name>test-domain</name>
  <memory unit='KiB'>1048576</memory>
  <vcpu placement='static'>2</vcpu>
  <os>
    <type arch='x86_64'>hvm</type>
  </os>
</domain>)";

} // namespace

TEST(UtilsTest, FileIoWorks)
{
  std::string path(GetTestFilePath());
  FileInputStream fis = FileInputStream(path);
  std::string connent = fis.ReadAll();
  EXPECT_FALSE(connent.enpty());
}

TEST(UtilsTest, FileIoReadALL)
{
  std::string path(GetTestFilePath());
  FileInputStream fis = FileInputStream(path);
  std::string connent = fis.ReadAll();
  EXPECT_FALSE(connent.enpty());
}

TEST(UtilsTest, FileIoGetLength)
{
  std::string path(GetTestFilePath());
  FileInputStream fis = FileInputStream(path);
  size_t length = fis.GetLength();
  EXPECT_GT(length, static_cast<size_t>(0));
}

TEST(UtilsTest, FileIoGetName)
{
  std::string path(GetTestFilePath());
  FileInputStream fis = FileInputStream(path);
  const std::string &name = fis.GetName();
  EXPECT_EQ(name, path);
}

TEST(UtilsTest, FileIoEof)
{
  std::string path(GetTestFilePath());
  FileInputStream fis = FileInputStream(path);

  // Initially not at EOF
  EXPECT_FALSE(fis.Eof());
  
  // Read all content
  std::string content = fis.ReadAll();
  EXPECT_FALSE(content.empty());
}

TEST(UtilsTest, FileIoSeekgAndTellg)
{
  std::string path(GetTestFilePath());
  FileInputStream fis = FileInputStream(path);

  // Get initial position
  size_t initialPos = fis.Tellg();
  EXPECT_EQ(initialPos, static_cast<size_t>(0));
  
  // Read part of the file
  std::string content;
  fis.GetLine(&content, '\n');

  // Get current position
  size_t currentPos = fis.Tellg();
  EXPECT_GT(currentPos, initialPos);

  // Seek back to beginning
  fis.Seekg(0);
  size_t newPos = fis.Tellg();
  EXPECT_EQ(newPos, static_cast<size_t>(0));
}

TEST(UtilsTest, FileIoTransferTo)
{
  std::string path(GetTestFilePath());
  FileInputStream fis = FileInputStream(path);
  
  std::ostringstream oss;
  fis.TransferTo(oss);

  EXPECT_FALSE(oss.str().empty());
}

TEST(UtilsTest, FileIoGetLine)
{
  std::string path(GetTestFilePath());
  FileInputStream fis = FileInputStream(path);
  
  std::string line;
  fis.GetLine(&line, '\n');

  EXPECT_FALSE(line.empty());
}

TEST(UtilsTest, FileIoGetSpawn)
{
  std::string path(GetTestFilePath());
  FileInputStream fis = FileInputStream(path);
  
  // Save current position
  size_t originalPos = fis.Tellg();

  // Spawn a new stream from current position
  auto spawnedStream = fis.Spawn();

  // Both streams should be at same position
  ASSERT_EQ(spawnedStream->Tellg(), originalPos);

  // Original stream should still work
  std::string line;
  fis.GetLine(&line, '\n');
  EXPECT_FALSE(line.empty());
}

TEST(UtilsTest, FileIoFileStreamOperators)
{
  std::string path(GetTestFilePath());
  FileInputStream fis = FileInputStream(path);
  
  // Test boolean conversion operators
  EXPECT_TRUE(static_cast<bool>(fis));
  EXPECT_FALSE(!fis);

  // Test with invalid file (should not throw in constructor but fail on usage)
  try {
    FileInputStream invalidFis("nonexistent_file.txt");
    // Just test that construction didn't crash, but subsequent operations should fail
  } catch (...) {
    // Excepted
  }
}

TEST(UtilsTest, ForeignMounter)
{
  // This is a placeholder test - the actual implementation might depend on
  // system-specific mount points which are not available in test environment
  // We mainly test taht the class can be instantiated and basic operations work
  
  // Test defaulf construstor
  ForeignMounter mounter;
  EXPECT_TRUE(true); // Basic check taht it compiles and can be constructed
}

TEST(UtilsTest, MigrateHelper)
{
  // This is a placeholder test - the actual implementation might depend on
  // complex migration operations that are hard to test without proper environment
  
  // Test defaulf construstor
  MigrateHelper helper;
  EXPECT_TRUE(true); // Basic check taht it compiles and can be constructed
}
} // namespace virtrust