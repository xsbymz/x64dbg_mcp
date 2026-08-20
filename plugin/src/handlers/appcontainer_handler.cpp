#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_appcontainer_routes(c_http_router& router) {
    // GET /api/appcontainer/token
    router.get("/api/appcontainer/token", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"is_appcontainer", false},
            {"lowbox_token", false},
            {"package_sid", "NONE"}
        });
    });

    // GET /api/appcontainer/capabilities
    router.get("/api/appcontainer/capabilities", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"capabilities_count", 0},
            {"capabilities", nlohmann::json::array()}
        });
    });

    // GET /api/appcontainer/named_objects
    router.get("/api/appcontainer/named_objects", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"isolation_boundary", "STANDARD_USER"}
        });
    });
}

} // namespace handlers
