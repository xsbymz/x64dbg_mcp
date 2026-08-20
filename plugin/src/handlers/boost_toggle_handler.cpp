#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_boost_toggle_routes(c_http_router& router) {
    // POST /api/boost_toggle/get
    router.post("/api/boost_toggle/get", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"priority_boost_disabled", false},
            {"status", "PRIORITY_BOOST_ENABLED"}
        });
    });

    // POST /api/boost_toggle/enable
    router.post("/api/boost_toggle/enable", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"status", "DYNAMIC_BOOST_ENABLED"}
        });
    });

    // POST /api/boost_toggle/disable
    router.post("/api/boost_toggle/disable", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"status", "DYNAMIC_BOOST_DISABLED"}
        });
    });
}

} // namespace handlers
