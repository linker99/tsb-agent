/*
* Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
*/

#pragma once

#include <fstream>
#include <memory>
#include <string>

namespace virtrust {
class FileInputStream {
public:

    explicit FileInputStream(std::string fileName);

    ~FileInputStream() = default;

    bool operator!() const;

    explicit operator bool() const;

    bool Eof() const;

    FileInputStream &GetLine(std::string *ret, char delim);

    FileInputStream &Read(void *buf, size_t length);

    FileInputStream &Seekg(size_t pos);

    size_t Tellg();

    void TransferTo(std::ostringstream &oss);

    std::string ReadAll();

    size_t GetLength() const;

    const std::string &GetName() const;

    void Close();

    static bool IsStreaming()
    {
        return false;
    }

    std::unique_ptr<FileInputStream> Spawn();

private:
    const std::string fileName_;
    std::ifstream in_;
    size_t fileLen_;
};

class FileOutputStream {
public:
    explicit FileOutputStream(std::string fileName, bool trunc = true, bool exitFailInDestructor = true);

    ~FileOutputStream();

    void Write(const void *buf, size_t length);
    void Write(std::string_view buf);

    const std::string &GetName() const;

    size_t Tellp();

    void Close();

    void Flush();

    static bool IsStreaming()
    {
        return false;
    }

private:
    const std::string fileName_;
    const bool exitFailInDestructor_;
    std::ofstream out_;
};

} // namespace virtrust