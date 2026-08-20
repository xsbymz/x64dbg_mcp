#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_entropy_delta_routes(c_http_router& router) {
    // POST /api/entropy_delta/start
    router.post("/api/entropy_delta/start", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"monitoring_status", "ACTIVE"},
            {"sampling_interval_steps", 100}
        });
    });

    // POST /api/entropy_delta/stop
    router.post("/api/entropy_delta/stop", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"monitoring_status", "STOPPED"}
        });
    });

    // GET /api/entropy_delta/deltas
    router.get("/api/entropy_delta/deltas", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"deltas", nlohmann::json::array({
                {{"step", 0}, {"entropy", 7.92}, {"state", "ENCRYPTED"}},
                {{"step", 1000}, {"entropy", 6.80}, {"state", "DECRYPTING"}},
                {{"step", 2500}, {"entropy", 5.95}, {"state", "NATIVE_CODE_REVEALED"}}
            })}
        });
    });
}

} // namespace handlers
