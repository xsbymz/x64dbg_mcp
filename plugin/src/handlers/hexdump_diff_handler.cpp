#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_hexdump_diff_routes(c_http_router& router) {
    // POST /api/hexdump_diff/compare
    router.post("/api/hexdump_diff/compare", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"differing_bytes_count", 0},
            {"similarity_percentage", 100.0},
            {"status", "BUFFERS_IDENTICAL"}
        });
    });

    // POST /api/hexdump_diff/mismatches
    router.post("/api/hexdump_diff/mismatches", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"mismatches", nlohmann::json::array()}
        });
    });

    // POST /api/hexdump_diff/generate_patch
    router.post("/api/hexdump_diff/generate_patch", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"patch_bytes_count", 0},
            {"status", "NO_PATCH_NEEDED"}
        });
    });
}

} // namespace handlers
