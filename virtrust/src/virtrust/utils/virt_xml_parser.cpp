#include "virtrust/utils/virt_xml_parser.h"

#include <filesystem>

namespace virtrust {

namespace {
constexpr std::string_view VIRT_XML_DISK_PATH = "/domain/devices/disk/source";
const xmlChar VIRT_XML_FILE_PROP[] = "file";
constexpr std::string_view VIRT_XML_LOADER_PATH = "/domain/os/loader";
constexpr std::string_view VIRT_XML_NAME_PATH = "/domain/name";
constexpr std::string_view PATH_SEPARATOR = "/";
} // namespace

void VirtXmlParser::SearchCurrLevel(std::vector<xmlNodePtr> &currLevel, std::vector<xmlNodePtr> &nextLevel,
                                    const std::string &nodeName)
{
    for (xmlNodePtr parent : currLevel) {
        for (xmlNodePtr node = parent->children; node != nullptr; node = node->next) {
            bool pathMatch = node->type == XML_ELEMENT_NODE && nodeName == MakeString(node->name);
            if (pathMatch) {
                nextLevel.push_back(node);
            }
        }
    }
}

std::vector<xmlNodePtr> VirtXmlParser::FindNodesByPath(std::string_view absPath)
{
    std::vector<xmlNodePtr> ret;
    auto root = libxml2_.xmlDocGetRootElement(doc_);
    if (root == nullptr) {
        VIRTRUST_LOG_ERROR("|FindNodesByPath|END|||Get xml root node failed.");
        return ret;
    }
    if (absPath.empty()) {
        VIRTRUST_LOG_ERROR("|FindNodesByPath|END|||Input path is empty.");
        return ret;
    }
    if (absPath[0] != '/') {
        VIRTRUST_LOG_ERROR("|FindNodesByPath|END||file path: {}|It's not a absolutely path.", absPath);
        return ret;
    }

    std::vector<std::string> parts = StrSplit(StrTrim(std::string(absPath), PATH_SEPARATOR[0]), PATH_SEPARATOR);

    std::vector<xmlNodePtr> currLevel = {root};
    if (parts[0] != MakeString(root->name)) {
        VIRTRUST_LOG_ERROR("|FindNodesByPath|END||file path: {}|The name of root node in xml file is wrong.", absPath);
        return ret;
    }

    for (size_t i = 1; i < parts.size(); ++i) {
        const auto &nodeName = parts[i];
        std::vector<xmlNodePtr> nextLevel;
        SearchCurrLevel(currLevel, nextLevel, nodeName);
        if (nextLevel.empty()) {  // No matchs found
            return ret;
        }
        currLevel = std::move(nextLevel);
    }
    return currLevel;
}

bool VirtXmlParser::LoadFile(std::string_view filename)
{
    if (filename.empty()) {
        VIRTRUST_LOG_ERROR("|LoadFile|END|returnF||File name is empty.");
        return false;
    }

    if (!std::filesystem::exists(filename) || !std::filesystem::is_regular_file(filename)) {
        VIRTRUST_LOG_ERROR("|LoadFile|END|returnF||The file does not exist: {}.", filename);
        return false;
    }

    // the reamining document tree if the file was wellformed, nullptr otherwise
    if (doc_ != nullptr) {
        VIRTRUST_LOG_WARN("|LoadFile|END|||Already load file, will load new one.");
        libxml2_.xmlFreeDoc(doc_);
        doc_ = nullptr;
    }
    doc_ = libxml2_.xmlParseFile(filename.data());
    return doc_ != nullptr;
}

std::string VirtXmlParser::GetDiskPath()
{
    auto nodes = FindNodesByPath(VIRT_XML_DISK_PATH);
    if (nodes.empty()) {
        VIRTRUST_LOG_ERROR("|GetDiskPath|END||node path: {}|Get disk path from xml failed.", VIRT_XML_DISK_PATH);
        return "";
    }

    if (nodes.size() != 1) {
        VIRTRUST_LOG_ERROR("|GetDiskPath|END|||The node of disk path in xml is not only.");
        return "";
    }

    xmlNodePtr node = nodes[0];
    xmlChar *diskPath = libxml2_.xmlGetProp(node, VIRT_XML_FILE_PROP);
    if (diskPath == nullptr) {
        VIRTRUST_LOG_ERROR("|GetDiskPath|END||node path: {}|Target node does not have property: {}.", VIRT_XML_DISK_PATH,
                            reinterpret_cast<const char*>(VIRT_XML_FILE_PROP));
        return "";
    }

    std::string ret = MakeString(diskPath);
    free(diskPath);
    return ret;
}

std::string VirtXmlParser::GetLoaderPath()
{
    auto nodes = FindNodesByPath(VIRT_XML_LOADER_PATH);
    if (nodes.empty()) {
        VIRTRUST_LOG_ERROR("|GetLoaderPath|END|||Get loader path from xml failed: {}.", VIRT_XML_LOADER_PATH);
        return "";
    }

    if (nodes.size() != 1) {
        VIRTRUST_LOG_ERROR("|GetLoaderPath|END|||The node of loader path in xml is not only.");
        return "";
    }

    xmlNodePtr node = nodes[0];
    if (node->children == nullptr || node->children->content == nullptr) {
        VIRTRUST_LOG_ERROR("|GetLoaderPath|END||node path: {}|Target node does not have any child nodes.",
                            VIRT_XML_LOADER_PATH);
        return "";
    }
    return MakeString(node->children->content);
}

std::string VirtXmlParser::GetVmName()
{
    auto nodes = FindNodesByPath(VIRT_XML_NAME_PATH);
    if (nodes.empty()) {
        VIRTRUST_LOG_ERROR("|GetVmName|END|||Get VM name from xml failed.");
        return "";
    }

    if (nodes.size() != 1) {
        VIRTRUST_LOG_ERROR("|GetVmName|END|||The node of VM name in xml is not only.");
        return "";
    }

    xmlNodePtr node = nodes[0];
    if (node->children == nullptr || node->children->content == nullptr) {
        VIRTRUST_LOG_ERROR("|GetVmName|END||node path: {}|Target node does not have any child nodes.",
                            VIRT_XML_NAME_PATH);
        return "";
    }
    return MakeString(node->children->content);
}

VerifyConfig VirtXmlParser::Parse(const std::string &filePath)
{
    LoadFile(filePath);
    VerifyConfig config(GetVmName(), GetDiskPath(), GetLoaderPath());
    return config;
}

} // namespace virtrust
