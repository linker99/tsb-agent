#ifndef TSB_AGENT_CONTEXT_H
#define TSB_AGENT_CONTEXT_H
#progma once
#include <memory>
#include <string>
namespace virtrust {

class ConnCtx {
public:
  using virConnectPrt = int *;
  ConnCtx();
  explicit ConnCtx(virConnectPrt conn) : conn_(conn) {}
  bool Connect();

  ConnCtx(const ConnCtx &) = delete;
  ConnCtx &operator=(const ConnCtx &) = delete;
  ~ConnCtx();
  bool SetUri(std::string uri);

  bool CheckOk() { return conn_ != nullptr; }
}

class DomainCtx {
public:
  using virDomainPtr = int *;
  DomainCtx() = default;
  explicit DomainCtx(virDomainPtr domain) : domain_(domain) {}
  explicit DomainCtx(const std::unique_ptr<ConnCtx> &conn,
                     const std::string &domainName);

  ~DomainCtx();
  DomainCtx(const DomainCtx &) = delete;
  DomainCtx &operator=(const DomainCtx &) = delete;

  bool CheckOk() { return domain_ != nullptr; }
  virDomainPtr Get() { return domain_; }

private:
  virDomainPtr domain_ = nullptr;
}

#endif // TSB_AGENT_CONTEXT_H