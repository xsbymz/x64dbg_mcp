#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_job_routes(c_http_router& router) {
    // GET /api/job/info
    router.get("/api/job/info", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"in_job_object", false},
            {"job_handle", "0x00000000"}
        });
    });

    // GET /api/job/limits
    router.get("/api/job/limits", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"has_cpu_rate_limit", false},
            {"has_memory_limit", false},
            {"limit_flags", "0x00000000"}
        });
    });

    // GET /api/job/processes
    router.get("/api/job/processes", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"processes_count", 0},
            {"process_ids", nlohmann::json::array()}
        });
    });
}

} // namespace handlers
