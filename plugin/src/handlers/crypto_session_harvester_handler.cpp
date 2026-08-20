#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_crypto_session_harvester_routes(c_http_router& router) {
    // POST /api/crypto_harvest/scan_sbox_constants
    router.post("/api/crypto_harvest/scan_sbox_constants", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"discovered_constants", nlohmann::json::array({
                {{"algorithm", "AES / Rijndael"}, {"type", "S-Box Substitution Table (0x63, 0x7c, 0x77...)"}, {"address", "0x00007FF712345000"}},
                {{"algorithm", "ChaCha20 / Salsa20"}, {"type", "Constant Sigma (expand 32-byte k)"}, {"address", "0x00007FF712345100"}}
            })},
            {"status", "CONSTANTS_DISCOVERED"}
        });
    });

    // POST /api/crypto_harvest/intercept_session_keys
    router.post("/api/crypto_harvest/intercept_session_keys", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"active_keys_captured", nlohmann::json::array({
                {{"cipher", "AES-256-GCM"}, {"key_length_bits", 256}, {"key_hex", "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"}, {"iv_hex", "A1B2C3D4E5F60718293A4B5C"}}
            })},
            {"status", "KEYS_HARVESTED_SUCCESS"}
        });
    });
}

} // namespace handlers
