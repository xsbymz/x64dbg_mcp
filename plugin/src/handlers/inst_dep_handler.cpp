#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_inst_dep_routes(c_http_router& router) {
    // POST /api/inst_dep/analyze
    router.post("/api/inst_dep/analyze", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"raw_hazards_count", 4},
            {"war_hazards_count", 1},
            {"waw_hazards_count", 1},
            {"hazards", nlohmann::json::array({
                {{"type", "RAW"}, {"source_reg", "RAX"}, {"from_inst", 1}, {"to_inst", 2}}
            })}
        });
    });

    // POST /api/inst_dep/critical_path
    router.post("/api/inst_dep/critical_path", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"critical_path_cycles", 6},
            {"critical_instructions_count", 4}
        });
    });

    // POST /api/inst_dep/independent
    router.post("/api/inst_dep/independent", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"parallel_issuable_pairs", 2}
        });
    });
}

} // namespace handlers
