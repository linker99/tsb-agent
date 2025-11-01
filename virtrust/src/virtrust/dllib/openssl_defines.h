#pragma once

namespace virtrust {

using EVP_MD = struct evp_md_st;
using EVP_MD_CTX = struct evp_md_ctx_st;
using OSSL_LIB_CTX = struct ossl_lib_ctx_st;

// openssl return value check
constexpr int OPENSSL_OK = 1;

} // namespace virtrust