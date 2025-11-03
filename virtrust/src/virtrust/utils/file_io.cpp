/*
* Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
*/

#include "virtrust/utils/file_io.h"

#include <cerrno>
#include <cstring>
#include <exception>
#include <filesystem>
#include <iostream>
#include <string>
#include <utility>

#include "spdlog/fmt/fmt.h"
#include "spdlog/spdlog.h"

#include "virtrust/base/exception.h"
#include "virtrust/base/logger.h"

namespace virtrust {
#define FILE_IO_THROW(msg_prefix)                                                                                  \
    VIRTRUST_ENFORCE(false, fmt::format("|{}|END|||error on file {}, failure {}", msg_prefix, fileName_, e.what(), \
                                        std::strerror(errno), errno))

FileInputStream::FileInputStream(std::string fileName) : fileName_(std::move(fileName)), fileLen_(0)
{
#ifndef __arm64__
    in_.exceptions(std::ifstream::badbit | std::ifstream::failbit);
#endif
    try {
        in_.open(fileName_, std::ios::binary | std::ios::ate);
    } catch (const std::ifstream::failure &e) {
        FILE_IO_THROW("Open for read");
    }
    fileLen_ = Tellg();
    Seekg(0);
}

bool FileInputStream::operator!() const
{
    return !static_cast<bool>(in_);
}

FileInputStream::operator bool() const
{
    return static_cast<bool>(in_);
}

bool FileInputStream::Eof() const
{
    return in_.eof();
}

FileInputStream &FileInputStream::GetLine(std::string *ret, char delim)
{
    try {
        std::getline(in_, *ret, delim);
    } catch (const std::ifstream::failure &e) {
        if (!in_.eof() || in_.bad()) {
            FILE_IO_THROW("GetLine");
        }
    }

    return *this;
}

FileInputStream &FileInputStream::Read(void *buf, size_t length)
{
    try {
        in_.read(static_cast<char *>(buf), length);
    } catch (const std::ifstream::failure &e) {
        FILE_IO_THROW("Read");
    }
    return *this;
}

FileInputStream &FileInputStream::Seekg(size_t pos)
{
    try {
        // clear EOF/FAIL bit
        in_.clear();
        in_.seekg(pos);
    } catch (const std::ifstream::failure &e) {
        FILE_IO_THROW("Seekg");
    }
    return *this;
}

size_t FileInputStream::Tellg()
{
    size_t ret = 0;
    try {
        auto backup = in_.rdstate();
        in_.clear();
        // tellg fail if eofbit is set.
        ret = in_.tellg();
        in_.clear(backup);
    } catch (const std::ifstream::failure &e) {
        if (in_.bad()) {
            FILE_IO_THROW("Tellg");
        }
    }
    return ret;
}

void FileInputStream::TransferTo(std::ostringstream &oss)
{
    try {
        // clear EOF/FAIL bit
        in_.clear();
        in_.seekg(0);
        oss << in_.rdbuf();
    } catch (const std::ifstream::failure &e) {
        FILE_IO_THROW("TransferTo");
    }
}

std::string FileInputStream::ReadAll()
{
    try {
        std::ostringstream oss;
        TransferTo(oss);
        return oss.str();
    } catch (const std::ifstream::failure &e) {
        FILE_IO_THROW("ReadAll");
    }
    return "";
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
    try {
        in_.close();
    } catch (const std::ifstream::failure &e) {
        FILE_IO_THROW("Close");
    }
    fileLen_ = 0;
}

std::unique_ptr<FileInputStream> FileInputStream::Spawn()
{
    auto ret = std::make_unique<FileInputStream>(fileName_);
    ret->Seekg(Tellg());
    return ret;
}

FileOutputStream::FileOutputStream(std::string fileName, bool trunc, bool exitFailInDestructor)
    : fileName_(std::move(fileName)), exitFailInDestructor_(exitFailInDestructor)
{
    std::filesystem::path fp(fileName_);
    // empty if relative path to pwd.
    if (!fp.parent_path().empty() && !std::filesystem::exists(fp.parent_path())) {
        VIRTRUST_ENFORCE(std::filesystem::create_directories(fp.parent_path()), "Failed to create dir ({})",
                         fp.parent_path().string());
    }
    out_.exceptions(std::ofstream::badbit | std::ofstream::failbit);
    try {
        out_.open(fileName_, std::ios::binary | (trunc ? std::ios::trunc : std::ios::app));
    } catch (const std::ofstream::failure &e) {
        FILE_IO_THROW("Open for write");
    }
}

FileOutputStream::~FileOutputStream()
{
    try {
        Close();
    } catch (const std::exception &e) {
        SPDLOG_ERROR("IO error in destructor: < {} >", e.what());
        if (exitFailInDestructor_) {
            _exit(-1);
        }
    }
}

void FileOutputStream::Write(const void *buf, size_t length)
{
    try {
        out_.write(static_cast<const char *>(buf), length);
    } catch (const std::ofstream::failure &e) {
        FILE_IO_THROW("Write");
    }
}

void FileOutputStream::Write(std::string_view buf)
{
    try {
        out_.write(buf.data(), buf.size());
    } catch (const std::ofstream::failure &e) {
        FILE_IO_THROW("Write");
    }
}

const std::string &FileOutputStream::GetName() const
{
    return fileName_;
}

size_t FileOutputStream::Tellp()
{
    size_t ret = 0;
    try {
        ret = out_.tellp();
    } catch (const std::ofstream::failure &e) {
        FILE_IO_THROW("Tellp");
    }
    return ret;
}

void FileOutputStream::Flush()
{
    try {
        if (out_.is_open() && out_.good()) {
            out_.flush();
        }
    } catch (const std::ofstream::failure &e) {
        FILE_IO_THROW("Flush");
    }
}

void FileOutputStream::Close()
{
    try {
        if (out_.is_open() && out_.good()) {
            Flush();
            out_.close();
        }
    } catch (const std::ofstream::failure &e) {
        FILE_IO_THROW("Close");
    }
}

} // namespace virtrust
