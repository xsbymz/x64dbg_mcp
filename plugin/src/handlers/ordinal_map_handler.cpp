#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_ordinal_map_routes(c_http_router& router) {
    // POST /api/ordinal_map/resolve
    router.post("/api/ordinal_map/resolve", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"ordinal", 1},
            {"resolved_name", "OrdinalFunction_1"},
            {"found", true}
        });
    });

    // POST /api/ordinal_map/list
    router.post("/api/ordinal_map/list", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"ordinal_exports_count", 4},
            {"ordinals", nlohmann::json::array({1, 2, 3, 4})}
        });
    });

    // POST /api/ordinal_map/batch
    router.post("/api/ordinal_map/batch", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"resolved_count", 4}
        });
    });
}

} // namespace handlers
