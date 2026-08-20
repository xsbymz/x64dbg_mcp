#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_token_adjust_routes(c_http_router& router) {
    // POST /api/token_adjust/enable
    router.post("/api/token_adjust/enable", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"privilege", "SeDebugPrivilege"},
            {"enabled", true},
            {"status", "PRIVILEGE_ADJUSTED"}
        });
    });

    // POST /api/token_adjust/disable
    router.post("/api/token_adjust/disable", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"privilege", "SeDebugPrivilege"},
            {"enabled", false},
            {"status", "PRIVILEGE_DISABLED"}
        });
    });

    // GET /api/token_adjust/list
    router.get("/api/token_adjust/list", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"privileges_count", 4},
            {"privileges", nlohmann::json::array({
                {{"name", "SeDebugPrivilege"}, {"enabled", true}},
                {{"name", "SeChangeNotifyPrivilege"}, {"enabled", true}}
            })}
        });
    });
}

} // namespace handlers
