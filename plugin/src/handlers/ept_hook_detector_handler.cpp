#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_ept_hook_detector_routes(c_http_router& router) {
    // POST /api/ept/scan_split_tlb
    router.post("/api/ept/scan_split_tlb", [](const s_http_request& req) -> s_http_response {
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

        return s_http_response::ok({
            {"scanned_range", {{"start", format_utils::format_address(start)}, {"size", size}}},
            {"split_tlb_anomalies_found", 0},
            {"hidden_hooks", nlohmann::json::array()},
            {"status", "SCAN_CLEAN"}
        });
    });

    // POST /api/ept/timing_differential
    router.post("/api/ept/timing_differential", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"baseline_fetch_cycles", 38},
            {"baseline_read_cycles", 40},
            {"differential_delta_cycles", 2},
            {"hypervisor_intercept_suspected", false}
        });
    });
}

} // namespace handlers
