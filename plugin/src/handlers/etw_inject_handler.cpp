#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_etw_inject_routes(c_http_router& router) {
    // POST /api/etw_inject/custom
    router.post("/api/etw_inject/custom", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"status", "ETW_EVENT_INJECTED"},
            {"event_dispatched", true}
        });
    });

    // POST /api/etw_inject/threat_intel
    router.post("/api/etw_inject/threat_intel", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"simulated_provider", "Microsoft-Windows-Threat-Intelligence"},
            {"status", "THREAT_INTEL_EVENT_SIMULATED"}
        });
    });

    // GET /api/etw_inject/handles
    router.get("/api/etw_inject/handles", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"registration_handles", nlohmann::json::array({
                "0x00007FFB80100000",
                "0x00007FFB80100400"
            })}
        });
    });
}

} // namespace handlers
