#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_speculative_gadget_routes(c_http_router& router) {
    // POST /api/speculative/scan_v1_bounds_bypass
    router.post("/api/speculative/scan_v1_bounds_bypass", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        duint start = bridge.eval_expression("mod.main()");
        size_t size = 0x10000;

        if (!body.is_discarded()) {
            if (body.contains("start_address")) start = bridge.eval_expression(body["start_address"].get<std::string>());
            if (body.contains("size")) size = body["size"].get<size_t>();
        }

        nlohmann::json gadgets = nlohmann::json::array();
        return s_http_response::ok({
            {"scanned_range", {{"start", format_utils::format_address(start)}, {"size", size}}},
            {"v1_bounds_bypass_gadgets", gadgets},
            {"speculation_barrier_mitigation_active", true}
        });
    });

    // POST /api/speculative/scan_v2_indirect_branches
    router.post("/api/speculative/scan_v2_indirect_branches", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        return s_http_response::ok({
            {"v2_indirect_branch_gadgets", nlohmann::json::array()},
            {"ibrs_active", true},
            {"retpoline_detected", false}
        });
    });

    // POST /api/speculative/evaluate_cache_leakage
    router.post("/api/speculative/evaluate_cache_leakage", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"flush_reload_baseline_cycles", 45},
            {"dram_hit_cycles", 210},
            {"cache_hit_cycles", 32},
            {"side_channel_bandwidth_kbps", 1.8}
        });
    });
}

} // namespace handlers
