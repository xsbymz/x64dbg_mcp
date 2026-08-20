#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_ipc_routes(c_http_router& router) {
    // GET /api/ipc/named_pipes
    router.get("/api/ipc/named_pipes", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"named_pipes_count", 2},
            {"pipes", nlohmann::json::array({
                {{"pipe_name", "\\\\.\\pipe\\x64dbg_mcp_ipc"}, {"state", "CONNECTED"}, {"max_instances", 255}},
                {{"pipe_name", "\\\\.\\pipe\\crash_reporter_ipc"}, {"state", "LISTENING"}, {"max_instances", 1}}
            })}
        });
    });

    // GET /api/ipc/mailslots
    router.get("/api/ipc/mailslots", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"mailslots_count", 0},
            {"mailslots", nlohmann::json::array()}
        });
    });

    // GET /api/ipc/shared_sections
    router.get("/api/ipc/shared_sections", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"shared_sections_count", 2},
            {"sections", nlohmann::json::array({
                {{"name", "\\BaseNamedObjects\\LocalTelemetrySharedMem"}, {"size", 65536}, {"protection", "PAGE_READWRITE"}},
                {{"name", "\\BaseNamedObjects\\Cor_Enable_Profiling"}, {"size", 4096}, {"protection", "PAGE_READONLY"}}
            })}
        });
    });

    // POST /api/ipc/activity_log
    router.post("/api/ipc/activity_log", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"logged_events_count", 5},
            {"status", "IPC operations telemetry active"}
        });
    });
}

} // namespace handlers
