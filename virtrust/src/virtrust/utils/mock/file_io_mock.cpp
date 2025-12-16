/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#ifdef VIRTRUST_MOCK

#include "virtrust/utils/file_io.h"

#include <sstream>
#include <unordered_map>
#include <cstring>

namespace virtrust {

// Mock content mapping for specific files
static std::unordered_map<std::string, std::string> mockFileContents = {
    {"bios_version", "7.12"},
    {".raw", "123456"},
    {"QEMU", "123456"},
    {"grub.cfg", "linux /boot/vmlinuz-5.10.0-60.18.0.50.oe1.x86_64 root=/dev/mapper/root ro\n"
                        "initrd /boot/initramfs-5.10.0-60.18.0.50.oe1.x86_64.img"},
};

// Mock global state to track file positions and content
static std::unordered_map<std::string, size_t> mockFilePositions;
static std::unordered_map<std::string, bool> mockFileEofStates;

// Helper function to get mock content for a filename
std::string GetMockContent(const std::string &fileName)
{
    // Check if filename contains any of our mock patterns
    for (const auto& [pattern, content] : mockFileContents) {
        if (fileName.find(pattern) != std::string::npos) {
            return content;
        }
    }

    // Return default mock content for any other file
    return "mock_file_content";
}

// Mock FileInputStream implementation
FileInputStream::FileInputStream(std::string fileName)
    : fileName_(std::move(fileName)), fileLen_(0)
{
    // Get mock content for this filename
    std::string content = GetMockContent(fileName_);
    fileLen_ = content.length();

    // Initialize file position for this file
    if (mockFilePositions.find(fileName_) == mockFilePositions.end()) {
        mockFilePositions[fileName_] = 0;
        mockFileEofStates[fileName_] = false;
    }
}

bool FileInputStream::operator!() const
{
    return false; // Mock implementation always succeeds
}

FileInputStream::operator bool() const
{
    return true; // Mock implementation always succeeds
}

bool FileInputStream::Eof() const
{
    return mockFileEofStates[fileName_];
}

FileInputStream &FileInputStream::GetLine(std::string &ret, char delim)
{
    std::string content = GetMockContent(fileName_);
    size_t currentPos = mockFilePositions[fileName_];

    if (currentPos >= content.length()) {
        mockFileEofStates[fileName_] = true;
        ret.clear();
        return *this;
    }

    // Find next delimiter or end of string
    size_t endPos = content.find(delim, currentPos);
    if (endPos == std::string::npos) {
        ret = content.substr(currentPos);
        mockFilePositions[fileName_] = content.length();
        mockFileEofStates[fileName_] = true;
    } else {
        ret = content.substr(currentPos, endPos - currentPos);
        mockFilePositions[fileName_] = endPos + 1; // Skip delimiter
        mockFileEofStates[fileName_] = (endPos + 1 >= content.length());
    }

    return *this;
}

FileInputStream &FileInputStream::Read(void *buf, size_t length)
{
    std::string content = GetMockContent(fileName_);
    size_t currentPos = mockFilePositions[fileName_];

    if (currentPos >= content.length()) {
        mockFileEofStates[fileName_] = true;
        return *this;
    }

    size_t readLength = std::min(length, content.length() - currentPos);
    if (readLength > 0) {
        memcpy(buf, content.data() + currentPos, readLength);
        mockFilePositions[fileName_] = currentPos + readLength;
    }

    if (mockFilePositions[fileName_] >= content.length()) {
        mockFileEofStates[fileName_] = true;
    }

    return *this;
}

FileInputStream &FileInputStream::Seekg(size_t pos)
{
    std::string content = GetMockContent(fileName_);
    mockFilePositions[fileName_] = std::min(pos, content.length());
    mockFileEofStates[fileName_] = false;
    return *this;
}

size_t FileInputStream::Tellg()
{
    return mockFilePositions[fileName_];
}

void FileInputStream::TransferTo(std::ostringstream &oss)
{
    std::string content = GetMockContent(fileName_);
    oss << content.substr(mockFilePositions[fileName_]);
    mockFilePositions[fileName_] = content.length();
    mockFileEofStates[fileName_] = true;
}

std::string FileInputStream::ReadAll()
{
    std::string content = GetMockContent(fileName_);
    mockFilePositions[fileName_] = content.length();
    mockFileEofStates[fileName_] = true;
    return content;
}

size_t FileInputStream::GetLength() const
{
    return fileLen_;
}

const std::string &FileInputStream::GetName() const
{
    return fileName_;
}

void FileInputStream::Close()
{
    // Reset file position for this file
    mockFilePositions[fileName_] = 0;
    mockFileEofStates[fileName_] = false;
}

std::unique_ptr<FileInputStream> FileInputStream::Spawn()
{
    auto ret = std::make_unique<FileInputStream>(fileName_);
    ret->Seekg(mockFilePositions[fileName_]);
    return ret;
}

// Mock FileOutputStream implementation
FileOutputStream::FileOutputStream(std::string fileName, bool trunc, bool exitFailInDestructor)
    : fileName_(std::move(fileName)), exitFailInDestructor_(exitFailInDestructor)
{
    // Mock implementation - just track that we "opened" the file
    (void)trunc; // Suppress unused parameter warning
    if (exitFailInDestructor_) {
        // do nothing
        return;
    }
}

FileOutputStream::~FileOutputStream()
{
    try {
        Close();
    } catch (const std::exception &e) {
        // In mock implementation, we don't exit on error
        (void)e;
    }
}

void FileOutputStream::Write(const void *buf, size_t length)
{
    // Mock implementation - just pretend to write
    (void)buf;
    (void)length;
}

void FileOutputStream::Write(std::string_view buf)
{
    // Mock implementation - just pretend to write
    (void)buf;
}

const std::string &FileOutputStream::GetName() const
{
    return fileName_;
}

size_t FileOutputStream::Tellp()
{
    // Mock implementation - return a fake position
    return 0;
}

void FileOutputStream::Flush()
{
    // Mock implementation - no actual flushing needed
}

void FileOutputStream::Close()
{
    // Mock implementation - no actual file to close
}

} // namespace virtrust

#endif // VIRTRUST_MOCK