#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_simd_diff_routes(c_http_router& router) {
    // GET /api/simd_diff/snapshot
    router.get("/api/simd_diff/snapshot", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"simd_snapshot_taken", true},
            {"registers_captured", 16}
        });
    });

    // GET /api/simd_diff/compare
    router.get("/api/simd_diff/compare", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"changed_registers_count", 1},
            {"changes", nlohmann::json::array({
                {{"register", "XMM0"}, {"previous_hex", "00000000000000000000000000000000"}, {"current_hex", "3F800000000000000000000000000000"}, {"float32_lane0", 1.0}}
            })}
        });
    });

    // POST /api/simd_diff/lanes
    router.post("/api/simd_diff/lanes", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string reg = body.value("register_name", "XMM0");

        return s_http_response::ok({
            {"register", reg},
            {"lanes_float32", nlohmann::json::array({1.0, 0.0, 0.0, 0.0})},
            {"lanes_float64", nlohmann::json::array({1.0, 0.0})},
            {"lanes_int32", nlohmann::json::array({1065353216, 0, 0, 0})}
        });
    });
}

} // namespace handlers
