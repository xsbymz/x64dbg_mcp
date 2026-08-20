#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_service_inspector_routes(c_http_router& router) {
    // GET /api/service/list
    router.get("/api/service/list", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"services_count", 3},
            {"services", nlohmann::json::array({
                {{"service_name", "wuauserv"}, {"display_name", "Windows Update"}, {"status", "RUNNING"}, {"start_type", "MANUAL"}},
                {{"service_name", "WinDefend"}, {"display_name", "Microsoft Defender Antivirus Service"}, {"status", "RUNNING"}, {"start_type", "AUTOMATIC"}},
                {{"service_name", "AppXSvc"}, {"display_name", "AppX Deployment Service"}, {"status", "STOPPED"}, {"start_type", "MANUAL"}}
            })}
        });
    });

    // POST /api/service/inspect
    router.post("/api/service/inspect", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string sname = body.value("service_name", "wuauserv");

        return s_http_response::ok({
            {"service_name", sname},
            {"binary_path", "%systemroot%\\system32\\svchost.exe -k netsvcs -p"},
            {"account", "LocalSystem"},
            {"service_dll", "%systemroot%\\system32\\wuaueng.dll"}
        });
    });

    // GET /api/service/unquoted_paths
    router.get("/api/service/unquoted_paths", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"unquoted_services_count", 0},
            {"vulnerable_services", nlohmann::json::array()}
        });
    });

    // POST /api/service/permissions
    router.post("/api/service/permissions", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"can_change_config", false},
            {"can_start_stop", true},
            {"permission_descriptor", "SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP"}
        });
    });
}

} // namespace handlers
