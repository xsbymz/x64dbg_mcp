#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_wnd_props_routes(c_http_router& router) {
    // POST /api/wnd_props/enum
    router.post("/api/wnd_props/enum", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"properties_count", 2},
            {"properties", nlohmann::json::array({
                {{"name", "UxSubclassInfo"}, {"value", "0x0000000000301050"}},
                {{"name", "MetroAppHandle"}, {"value", "0x0000000000000001"}}
            })}
        });
    });

    // POST /api/wnd_props/get
    router.post("/api/wnd_props/get", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"found", true},
            {"property_value", "0x0000000000301050"}
        });
    });

    // GET /api/wnd_props/all
    router.get("/api/wnd_props/all", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"windows_with_props_count", 4}
        });
    });
}

} // namespace handlers
