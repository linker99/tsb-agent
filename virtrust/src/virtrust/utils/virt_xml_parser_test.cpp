/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include <filesystem>
#include <fstream>

#include "gtest/gtest.h"

#include "virtrust/utils/virt_xml_parser.h"

namespace virtrust {

namespace {
std::string GetTestXml()
{
    auto filePath = std::filesystem::path(__FILE__);
    return (filePath / ".." / ".." / ".." / ".." / "test" / "data" / "test.xml").lexically_normal().string();
}

constexpr std::string_view TEST_GUEST_NAME = "open-euler-vm";
constexpr std::string_view TEST_DISK_PATH = "/data/images/openEuler-24.03-LTS-SP1-x86_64.qcow2";
constexpr std::string_view TEST_LOADER_PATH = "";
constexpr std::string_view TEST_SHIM_PATH = "/boot/efi/EFI/openEuler/shimaa64.efi";
constexpr std::string_view TEST_GRUB_PATH = "/boot/efi/EFI/openEuler/grubaa64.efi";
constexpr std::string_view TEST_GRUB_CFG_PATH = "/boot/efi/EFI/openEuler/grub.cfg";
} // namespace

TEST(VirtXmlParserTest, ParseTest)
{
    auto parse = VirtXmlParser();
    auto config = parse.Parse(GetTestXml());

    EXPECT_EQ(config.GetGuestName(), TEST_GUEST_NAME);
    EXPECT_EQ(config.GetDiskPath(), TEST_DISK_PATH);
    EXPECT_EQ(config.GetLoaderPath(), TEST_LOADER_PATH);
    EXPECT_EQ(config.GetShimPath(), TEST_SHIM_PATH);
    EXPECT_EQ(config.GetGrubPath(), TEST_GRUB_PATH);
    EXPECT_EQ(config.GetGrubCfgPath(), TEST_GRUB_CFG_PATH);
}

TEST(VirtXmlParserTest, LoadFileTest)
{
    // Test valid file loading
    auto parse = VirtXmlParser();
    EXPECT_TRUE(parse.LoadFile(GetTestXml()));

    // Test invalid file path
    EXPECT_FALSE(parse.LoadFile("/non/existent/file.xml"));

    // Test empty file name
    EXPECT_FALSE(parse.LoadFile(""));
}

TEST(VirtXmlParserTest, FindNodesByPathTest)
{
    auto parse = VirtXmlParser();
    EXPECT_TRUE(parse.LoadFile(GetTestXml()));

    // Test valid file path
    auto nodes = parse.FindNodesByPath("/domain/name");
    EXPECT_EQ(nodes.size(), 1UL);

    // Test invalid file path
    auto emptyNodes = parse.FindNodesByPath("/domain/nonexistent");
    EXPECT_TRUE(emptyNodes.empty());

    // Test empty path
    auto emptyPathNodes = parse.FindNodesByPath("");
    EXPECT_TRUE(emptyPathNodes.empty());

    // Test non-absolute path
    auto nonAbsNodes = parse.FindNodesByPath("domain/name");
    EXPECT_TRUE(nonAbsNodes.empty());
}
} // namespace virtrust