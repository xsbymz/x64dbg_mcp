#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_stream_cipher_routes(c_http_router& router) {
    // GET /api/stream_cipher/rc4
    router.get("/api/stream_cipher/rc4", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"rc4_states_found", 0},
            {"candidates", nlohmann::json::array()}
        });
    });

    // GET /api/stream_cipher/chacha20
    router.get("/api/stream_cipher/chacha20", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"chacha20_constants_found", 0},
            {"has_expand_32_byte_k", false}
        });
    });

    // GET /api/stream_cipher/detect
    router.get("/api/stream_cipher/detect", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"detected_stream_ciphers_count", 0},
            {"status", "NO_STREAM_CIPHERS_ACTIVE"}
        });
    });
}

} // namespace handlers
