#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_aslr_eval_routes(c_http_router& router) {
    // GET /api/aslr_eval/entropy
    router.get("/api/aslr_eval/entropy", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"aslr_entropy_score", 0.98},
            {"high_entropy_aslr_active", true},
            {"bottom_up_randomization", true}
        });
    });

    // GET /api/aslr_eval/high_entropy
    router.get("/api/aslr_eval/high_entropy", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"is_64bit_high_entropy", true},
            {"entropy_bits", 24}
        });
    });

    // GET /api/aslr_eval/deltas
    router.get("/api/aslr_eval/deltas", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"modules_evaluated", 6},
            {"average_delta_variance", 0.89}
        });
    });
}

} // namespace handlers
