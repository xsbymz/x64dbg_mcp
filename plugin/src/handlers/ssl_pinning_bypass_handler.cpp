#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_ssl_pinning_bypass_routes(c_http_router& router) {
    router.post("/api/ssl_pinning/detect_pinned_hashes", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        DWORD targetPid = body.value("pid", (DWORD)GetCurrentProcessId());
        json result;
        result["pid"] = targetPid;
        result["pinning_patterns"] = {
            {"SPKI_SHA256", "Subject Public Key Info SHA-256 base64 / hex hashes embedded in binary constants"},
            {"Certificate_DER", "Embedded raw X.509 DER certificate binaries in resource (.rsrc) section"},
            {"Public_Key_Modulus", "Hardcoded RSA 2048/4096 modulus arrays used in custom verification routines"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/ssl_pinning/locate_validation_callbacks", [](const s_http_request& req) {
        json result;
        result["windows_tls_validation_hooks"] = {
            {"WinHTTP", "WINHTTP_CALLBACK_STATUS_SENDING_REQUEST / WINHTTP_CALLBACK_FLAG_HANDSHAKE_CERT"},
            {"WinINet", "InternetSetStatusCallback / SECURITY_FLAG_IGNORE_*"},
            {"Schannel", "CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, ...)"},
            {"OpenSSL", "SSL_CTX_set_verify / SSL_CTX_set_cert_verify_callback"},
            {"Chromium_Network_Service", "CertVerifier / SSLClientSocketImpl validation procedures"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/ssl_pinning/generate_bypass_strategy", [](const s_http_request& req) {
        json result;
        result["bypass_hooks"] = {
            {"CertVerifyCertificateChainPolicy", "Patch return value to TRUE (1) and pPolicyStatus.dwError to 0"},
            {"WinHttpSetOption", "Force WINHTTP_OPTION_SECURITY_FLAGS = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID"},
            {"SSL_CTX_set_verify", "Set mode parameter to SSL_VERIFY_NONE (0)"}
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

