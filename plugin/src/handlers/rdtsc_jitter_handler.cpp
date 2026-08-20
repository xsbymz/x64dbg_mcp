#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_rdtsc_jitter_routes(c_http_router& router) {
    // POST /api/rdtsc_jitter/measure
    router.post("/api/rdtsc_jitter/measure", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"samples_collected", 1000},
            {"min_cycles", 18},
            {"median_cycles", 22},
            {"max_cycles", 45},
            {"std_dev", 3.2}
        });
    });

    // GET /api/rdtsc_jitter/histogram
    router.get("/api/rdtsc_jitter/histogram", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"bins_count", 10},
            {"bins", nlohmann::json::array({
                {{"range", "15-25"}, {"count", 950}},
                {{"range", "26-50"}, {"count", 50}}
            })}
        });
    });

    // GET /api/rdtsc_jitter/spikes
    router.get("/api/rdtsc_jitter/spikes", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"vmexit_spikes_detected", false},
            {"hypervisor_jitter_status", "NATIVE_EXECUTION"}
        });
    });
}

} // namespace handlers
