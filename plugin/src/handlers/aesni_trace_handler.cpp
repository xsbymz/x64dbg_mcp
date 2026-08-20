#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_aesni_trace_routes(c_http_router& router) {
    // POST /api/aesni_trace/trace
    router.post("/api/aesni_trace/trace", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"captured_aesni_events_count", 0},
            {"events", nlohmann::json::array()}
        });
    });

    // GET /api/aesni_trace/keys
    router.get("/api/aesni_trace/keys", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"round_keys_extracted", 0}
        });
    });

    // GET /api/aesni_trace/loops
    router.get("/api/aesni_trace/loops", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"detected_aes_loops_count", 0}
        });
    });
}

} // namespace handlers
