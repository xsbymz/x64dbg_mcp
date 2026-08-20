#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_dcom_surrogate_routes(c_http_router& router) {
    // GET /api/dcom_surrogate/processes
    router.get("/api/dcom_surrogate/processes", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"surrogate_processes_count", 0},
            {"processes", nlohmann::json::array()}
        });
    });

    // POST /api/dcom_surrogate/appid_permissions
    router.post("/api/dcom_surrogate/appid_permissions", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string appid = body.value("appid", "{00000000-0000-0000-0000-000000000000}");

        return s_http_response::ok({
            {"appid", appid},
            {"run_as", "Interactive User"},
            {"launch_permission", "INTERACTIVE, SYSTEM, ADMINISTRATORS"}
        });
    });

    // GET /api/dcom_surrogate/endpoints
    router.get("/api/dcom_surrogate/endpoints", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"endpoints", nlohmann::json::array()}
        });
    });
}

} // namespace handlers
