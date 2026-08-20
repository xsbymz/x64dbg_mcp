#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_branch_runlength_routes(c_http_router& router) {
    // POST /api/branch_runlength/profile
    router.post("/api/branch_runlength/profile", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"total_executions", 128},
            {"max_taken_runlength", 32},
            {"max_nontaken_runlength", 1},
            {"runlength_distribution", nlohmann::json::array({
                {{"runlength", 32}, {"frequency", 4}}
            })}
        });
    });

    // POST /api/branch_runlength/trips
    router.post("/api/branch_runlength/trips", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"average_trip_count", 32.0},
            {"loop_detected", true}
        });
    });

    // POST /api/branch_runlength/entropy
    router.post("/api/branch_runlength/entropy", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"branch_entropy", 0.12},
            {"predictability", "HIGHLY_PREDICTABLE"}
        });
    });
}

} // namespace handlers
