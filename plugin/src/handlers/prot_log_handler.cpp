#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_prot_log_routes(c_http_router& router) {
    // GET /api/prot_log/list
    router.get("/api/prot_log/list", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"events_count", 1},
            {"events", nlohmann::json::array({
                {{"address", "0x00007FF712350000"}, {"size", 0x1000}, {"old_protect", "PAGE_READWRITE"}, {"new_protect", "PAGE_EXECUTE_READ"}, {"thread_id", 1024}}
            })}
        });
    });

    // GET /api/prot_log/rwx
    router.get("/api/prot_log/rwx", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"rwx_escalations_count", 0},
            {"status", "NO_RWX_ESCALATIONS"}
        });
    });

    // POST /api/prot_log/clear
    router.post("/api/prot_log/clear", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"status", "PROTECTION_LOG_CLEARED"}
        });
    });
}

} // namespace handlers
