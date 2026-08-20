#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_inst_side_effects_routes(c_http_router& router) {
    // POST /api/inst_side_effects/predict
    router.post("/api/inst_side_effects/predict", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"modified_registers", nlohmann::json::array({"RAX"})},
            {"written_memory", false},
            {"branch_taken", false}
        });
    });

    // POST /api/inst_side_effects/flags
    router.post("/api/inst_side_effects/flags", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"modified_flags", nlohmann::json::array({"ZF", "SF", "PF"})},
            {"cleared_flags", nlohmann::json::array({"OF", "CF"})}
        });
    });

    // POST /api/inst_side_effects/stack
    router.post("/api/inst_side_effects/stack", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"stack_displacement_bytes", 0}
        });
    });
}

} // namespace handlers
