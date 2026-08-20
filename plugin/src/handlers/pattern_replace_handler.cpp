#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_pattern_replace_routes(c_http_router& router) {
    // POST /api/pattern_replace/search
    router.post("/api/pattern_replace/search", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"matches_count", 2},
            {"matches", nlohmann::json::array({
                "0x00007FF712341050",
                "0x00007FF712342120"
            })}
        });
    });

    // POST /api/pattern_replace/replace_all
    router.post("/api/pattern_replace/replace_all", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"replacements_applied_count", 2},
            {"status", "PATTERN_REPLACED"}
        });
    });

    // POST /api/pattern_replace/replace_once
    router.post("/api/pattern_replace/replace_once", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"replacements_applied_count", 1},
            {"replaced_at", "0x00007FF712341050"}
        });
    });
}

} // namespace handlers
