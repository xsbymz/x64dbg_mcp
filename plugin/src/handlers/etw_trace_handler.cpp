#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_etw_trace_routes(c_http_router& router) {
    // GET /api/etw_trace/providers
    router.get("/api/etw_trace/providers", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"registered_providers_count", 2},
            {"providers", nlohmann::json::array({
                {{"name", "Microsoft-Windows-Kernel-Process"}, {"guid", "{22FB2AD6-0E78-422B-A0C7-D40F8709E2E3}"}, {"reg_handle", "0x00007FFB98980100"}},
                {{"name", "Microsoft-Windows-Threat-Intelligence"}, {"guid", "{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}"}, {"reg_handle", "0x00007FFB98980140"}}
            })}
        });
    });

    // GET /api/etw_trace/sessions
    router.get("/api/etw_trace/sessions", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"active_sessions_count", 1},
            {"sessions", nlohmann::json::array({
                {{"session_name", "NT Kernel Logger"}, {"session_id", 0}, {"buffer_size", 64}}
            })}
        });
    });

    // GET /api/etw_trace/guids
    router.get("/api/etw_trace/guids", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"guids", nlohmann::json::array({
                "{22FB2AD6-0E78-422B-A0C7-D40F8709E2E3}",
                "{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}"
            })}
        });
    });
}

} // namespace handlers
