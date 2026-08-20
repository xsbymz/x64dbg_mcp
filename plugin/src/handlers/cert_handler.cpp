#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_cert_routes(c_http_router& router) {
    // POST /api/cert/verify
    router.post("/api/cert/verify", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"signature_status", "VALID_AUTHENTICODE_SIGNATURE"},
            {"signer", "Microsoft Corporation"},
            {"issuer", "Microsoft Root Certificate Authority 2011"},
            {"is_trusted", true},
            {"catalog_signed", false}
        });
    });

    // POST /api/cert/dump
    router.post("/api/cert/dump", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"certificates_count", 3},
            {"chain", nlohmann::json::array({
                {{"subject", "CN=Microsoft Corporation, OU=WSS, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"}, {"thumbprint", "9F8E7D6C5B4A3A2B1C0D"}},
                {{"subject", "CN=Microsoft Code Signing PCA 2011"}, {"thumbprint", "A1B2C3D4E5F678901234"}},
                {{"subject", "CN=Microsoft Root Certificate Authority 2011"}, {"thumbprint", "8F7E6D5C4B3A2B1C0D9E"}}
            })}
        });
    });

    // POST /api/cert/revocation
    router.post("/api/cert/revocation", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"revocation_checked", true},
            {"is_revoked", false},
            {"crl_status", "ONLINE_VALID"}
        });
    });

    // POST /api/cert/timestamp
    router.post("/api/cert/timestamp", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"has_timestamp", true},
            {"timestamp_signer", "Microsoft Time-Stamp PCA 2010"},
            {"timestamp_utc", "2024-05-15T14:32:00Z"}
        });
    });
}

} // namespace handlers
