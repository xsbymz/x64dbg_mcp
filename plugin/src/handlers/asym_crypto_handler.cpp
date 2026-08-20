#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_asym_crypto_routes(c_http_router& router) {
    // POST /api/asym_crypto/rsa
    router.post("/api/asym_crypto/rsa", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"rsa_keys_found", 0},
            {"candidates", nlohmann::json::array()}
        });
    });

    // POST /api/asym_crypto/ecc
    router.post("/api/asym_crypto/ecc", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"ecc_curves_found", 0},
            {"candidates", nlohmann::json::array()}
        });
    });

    // POST /api/asym_crypto/pkcs1
    router.post("/api/asym_crypto/pkcs1", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"is_valid_pkcs1", false}
        });
    });
}

} // namespace handlers
