#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_rot_table_routes(c_http_router& router) {
    // GET /api/rot_table/enum
    router.get("/api/rot_table/enum", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"rot_objects_count", 0},
            {"objects", nlohmann::json::array()}
        });
    });

    // POST /api/rot_table/name
    router.post("/api/rot_table/name", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"display_name", "ItemMoniker_01"}
        });
    });

    // POST /api/rot_table/context
    router.post("/api/rot_table/context", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"bind_flags", "BIND_MAYBOTHERUSER (1)"}
        });
    });
}

} // namespace handlers
