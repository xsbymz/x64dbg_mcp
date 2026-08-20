#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_mem_commit_routes(c_http_router& router) {
    // GET /api/mem_commit/counters
    router.get("/api/mem_commit/counters", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"working_set_size_bytes", 24576000},
            {"pagefile_usage_bytes", 32800000},
            {"private_bytes", 18450000},
            {"peak_working_set_bytes", 28000000}
        });
    });

    // GET /api/mem_commit/growth
    router.get("/api/mem_commit/growth", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"growth_rate_bytes_per_step", 128},
            {"commit_trend", "STABLE"}
        });
    });

    // GET /api/mem_commit/ranges
    router.get("/api/mem_commit/ranges", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"committed_ranges_count", 8},
            {"ranges", nlohmann::json::array({
                {{"base", "0x00007FF712340000"}, {"size", 0x40000}, {"type", "MEM_COMMIT"}}
            })}
        });
    });
}

} // namespace handlers
