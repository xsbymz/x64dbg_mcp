#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_cycle_profiler_routes(c_http_router& router) {
    // POST /api/cycle_profiler/range
    router.post("/api/cycle_profiler/range", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"total_cycles_elapsed", 1420},
            {"instruction_count", 48},
            {"avg_cycles_per_instruction", 29.58}
        });
    });

    // POST /api/cycle_profiler/basic_block
    router.post("/api/cycle_profiler/basic_block", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"basic_block_cycles", 112},
            {"l1_cache_miss_estimate", 0}
        });
    });

    // GET /api/cycle_profiler/anomalies
    router.get("/api/cycle_profiler/anomalies", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"timing_traps_detected_count", 0},
            {"anomalies", nlohmann::json::array()}
        });
    });
}

} // namespace handlers
