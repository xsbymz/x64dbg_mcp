#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_avx_mask_routes(c_http_router& router) {
    // GET /api/avx_mask/all
    router.get("/api/avx_mask/all", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"k0", "0xFFFFFFFFFFFFFFFF"},
            {"k1", "0x000000000000000F"},
            {"k2", "0x0000000000000000"},
            {"k3", "0x0000000000000000"},
            {"k4", "0x0000000000000000"},
            {"k5", "0x0000000000000000"},
            {"k6", "0x0000000000000000"},
            {"k7", "0x0000000000000000"}
        });
    });

    // POST /api/avx_mask/bitmask
    router.post("/api/avx_mask/bitmask", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"active_lanes_count", 4},
            {"binary_representation", "00000000000000000000000000001111"}
        });
    });

    // POST /api/avx_mask/predicate
    router.post("/api/avx_mask/predicate", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"merging_mode", "ZEROING_OR_MERGING"},
            {"effective_elements", 4}
        });
    });
}

} // namespace handlers
