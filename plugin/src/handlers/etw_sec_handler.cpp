#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_etw_sec_routes(c_http_router& router) {
    // GET /api/etw_sec/providers
    router.get("/api/etw_sec/providers", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"providers", nlohmann::json::array({
                "Microsoft-Windows-Security-Mitigations",
                "Microsoft-Windows-Kernel-Audit-API-Calls",
                "Microsoft-Windows-Threat-Intelligence"
            })}
        });
    });

    // GET /api/etw_sec/capture
    router.get("/api/etw_sec/capture", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"events_captured", 0},
            {"status", "LISTENING"}
        });
    });

    // GET /api/etw_sec/guids
    router.get("/api/etw_sec/guids", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"threat_intel_guid", "{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}"}
        });
    });
}

} // namespace handlers
