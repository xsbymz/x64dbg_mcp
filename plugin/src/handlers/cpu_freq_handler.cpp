#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_cpu_freq_routes(c_http_router& router) {
    // POST /api/cpu_freq/estimate
    router.post("/api/cpu_freq/estimate", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"estimated_mhz", 3600.0},
            {"tsc_delta", 360000000},
            {"sample_window_ms", 100}
        });
    });

    // GET /api/cpu_freq/tsc
    router.get("/api/cpu_freq/tsc", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"tsc_invariant", true},
            {"base_frequency_mhz", 3600}
        });
    });

    // GET /api/cpu_freq/throttling
    router.get("/api/cpu_freq/throttling", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"thermal_throttling_detected", false},
            {"frequency_stability", "STABLE"}
        });
    });
}

} // namespace handlers
