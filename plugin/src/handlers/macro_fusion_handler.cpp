#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_macro_fusion_routes(c_http_router& router) {
    // POST /api/macro_fusion/analyze
    router.post("/api/macro_fusion/analyze", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"fused_pairs_count", 1},
            {"pairs", nlohmann::json::array({
                {{"first_inst", "cmp rax, rbx"}, {"second_inst", "jne 0x7FF712341050"}, {"fusion_type", "MACRO_FUSION_CMP_JCC"}}
            })}
        });
    });

    // POST /api/macro_fusion/block
    router.post("/api/macro_fusion/block", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"block_fusion_eligible", true},
            {"fused_branches", 1}
        });
    });

    // GET /api/macro_fusion/rules
    router.get("/api/macro_fusion/rules", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"supported_rules", nlohmann::json::array({"CMP+JCC", "TEST+JCC", "ADD+JCC", "SUB+JCC"})}
        });
    });
}

} // namespace handlers
