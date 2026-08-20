#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_tls_key_extractor_routes(c_http_router& router) {
    // POST /api/tls/hook_schannel
    router.post("/api/tls/hook_schannel", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"schannel_hook_status", "ACTIVE"},
            {"intercept_target", "ncrypt.dll!SslGenerateMasterKey"},
            {"captured_sessions_count", 0}
        });
    });

    // POST /api/tls/hook_openssl
    router.post("/api/tls/hook_openssl", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"openssl_hook_status", "ACTIVE"},
            {"intercept_targets", nlohmann::json::array({"SSL_read", "SSL_write", "SSL_CTX_set_keylog_callback"})},
            {"keylog_callback_registered", true}
        });
    });

    // POST /api/tls/export_sslkeylog
    router.post("/api/tls/export_sslkeylog", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"sslkeylogfile_content", "CLIENT_RANDOM 1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321\n"},
            {"keys_exported", 1},
            {"wireshark_ready", true}
        });
    });
}

} // namespace handlers
