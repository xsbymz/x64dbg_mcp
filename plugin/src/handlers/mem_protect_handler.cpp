#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_mem_protect_routes(c_http_router& router) {
    // GET /api/mem_protect/transitions
    router.get("/api/mem_protect/transitions", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"transitions_count", 2},
            {"transitions", nlohmann::json::array({
                {{"address", "0x0000021A58900000"}, {"size", 4096}, {"old_protect", "PAGE_READWRITE (0x04)"}, {"new_protect", "PAGE_EXECUTE_READ (0x20)"}},
                {{"address", "0x0000021A58910000"}, {"size", 8192}, {"old_protect", "PAGE_READWRITE (0x04)"}, {"new_protect", "PAGE_EXECUTE_READWRITE (0x40)"}}
            })}
        });
    });

    // GET /api/mem_protect/rwx_events
    router.get("/api/mem_protect/rwx_events", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"rwx_events_count", 1},
            {"events", nlohmann::json::array({
                {{"address", "0x0000021A58910000"}, {"size", 8192}, {"caller", "0x00007FF712341500"}, {"warning", "W^X_VIOLATION_RWX_PAGE_ALLOCATED"}}
            })}
        });
    });

    // POST /api/mem_protect/clear
    router.post("/api/mem_protect/clear", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"status", "PROTECTION_TRANSITIONS_CLEARED"}
        });
    });
}

} // namespace handlers
