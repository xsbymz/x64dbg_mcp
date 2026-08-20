#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_branch_sim_routes(c_http_router& router) {
    // POST /api/branch_sim/trace
    router.post("/api/branch_sim/trace", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"simulated_predictions_count", 32},
            {"mispredictions_count", 2},
            {"accuracy_percentage", 93.75}
        });
    });

    // GET /api/branch_sim/misprediction_rate
    router.get("/api/branch_sim/misprediction_rate", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"misprediction_rate", 0.0625},
            {"estimated_pipeline_flush_cycles", 30}
        });
    });

    // GET /api/branch_sim/bht_state
    router.get("/api/branch_sim/bht_state", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"bht_entries_active", 16},
            {"predictor_type", "TWO_LEVEL_ADAPTIVE_PHT"}
        });
    });
}

} // namespace handlers
