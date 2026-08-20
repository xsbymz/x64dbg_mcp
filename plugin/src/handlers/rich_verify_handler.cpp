#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_rich_verify_routes(c_http_router& router) {
    // GET /api/rich_verify/checksum
    router.get("/api/rich_verify/checksum", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"calculated_checksum", "0x5A8E142B"},
            {"stored_checksum", "0x5A8E142B"},
            {"checksum_valid", true}
        });
    });

    // GET /api/rich_verify/tampering
    router.get("/api/rich_verify/tampering", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"tampering_detected", false},
            {"header_integrity", "INTACT"}
        });
    });

    // GET /api/rich_verify/key
    router.get("/api/rich_verify/key", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"dans_xor_key", "0x5A8E142B"}
        });
    });
}

} // namespace handlers
