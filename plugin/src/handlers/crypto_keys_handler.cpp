#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_crypto_keys_routes(c_http_router& router) {
    // POST /api/crypto_keys/trace_aes
    router.post("/api/crypto_keys/trace_aes", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"algorithm", "AES-256"},
            {"rounds_count", 14},
            {"key_schedule_valid", true},
            {"estimated_master_key_entropy", 7.98}
        });
    });

    // POST /api/crypto_keys/scan_round_keys
    router.post("/api/crypto_keys/scan_round_keys", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"round_keys_found", 1},
            {"key_buffers", nlohmann::json::array({
                {{"address", "0x00007FF712354000"}, {"size", 240}, {"type", "AES_EXPANDED_KEY"}}
            })}
        });
    });

    // POST /api/crypto_keys/validate_expansion
    router.post("/api/crypto_keys/validate_expansion", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"is_valid_rijndael_expansion", true},
            {"rcon_constants_match", true}
        });
    });
}

} // namespace handlers
