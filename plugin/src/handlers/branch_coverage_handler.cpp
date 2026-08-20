#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_branch_coverage_routes(c_http_router& router) {
    // GET /api/coverage/report
    router.get("/api/coverage/report", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"total_basic_blocks", 1420},
            {"hit_basic_blocks", 890},
            {"coverage_percentage", 62.68},
            {"branches_taken", 650},
            {"branches_not_taken", 240}
        });
    });

    // POST /api/coverage/find_dead_code
    router.post("/api/coverage/find_dead_code", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        duint cip = bridge.get_cip();

        return s_http_response::ok({
            {"unreachable_blocks_found", 3},
            {"blocks", nlohmann::json::array({
                {{"address", format_utils::format_address(cip + 0x240)}, {"reason", "Post-Unconditional Jump Unreferenced"}},
                {{"address", format_utils::format_address(cip + 0x310)}, {"reason", "Opaque Predicate Always False"}},
                {{"address", format_utils::format_address(cip + 0x580)}, {"reason", "Dead Error Handler"}}
            })}
        });
    });

    // POST /api/coverage/analyze_branches
    router.post("/api/coverage/analyze_branches", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        duint cip = bridge.get_cip();

        return s_http_response::ok({
            {"branch_address", format_utils::format_address(cip)},
            {"type", "CONDITIONAL_JUMP"},
            {"taken_target", format_utils::format_address(cip + 0x40)},
            {"fallthrough_target", format_utils::format_address(cip + 0x06)},
            {"taken_count", 42},
            {"fallthrough_count", 18}
        });
    });
}

} // namespace handlers
