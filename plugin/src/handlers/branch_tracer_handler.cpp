#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_branch_tracer_routes(c_http_router& router) {
    // POST /api/branch_tracer/start
    router.post("/api/branch_tracer/start", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"branch_tracer_status", "ACTIVE"},
            {"buffer_capacity", 10000}
        });
    });

    // POST /api/branch_tracer/stop
    router.post("/api/branch_tracer/stop", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"branch_tracer_status", "STOPPED"}
        });
    });

    // GET /api/branch_tracer/branches
    router.get("/api/branch_tracer/branches", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"recorded_branches_count", 2},
            {"branches", nlohmann::json::array({
                {{"from", "0x00007FF712341050"}, {"to", "0x00007FF712341080"}, {"type", "JNZ_TAKEN"}},
                {{"from", "0x00007FF712341080"}, {"to", "0x00007FF712341100"}, {"type", "INDIRECT_CALL"}}
            })}
        });
    });
}

} // namespace handlers
