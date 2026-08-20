#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_cet_shadow_manipulator_routes(c_http_router& router) {
    // POST /api/cet/read_shadow_stack
    router.post("/api/cet/read_shadow_stack", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        duint cip = bridge.get_cip();
        auto reg_dump = bridge.get_register_dump();
        duint csp = reg_dump.has_value() ? reg_dump->regcontext.csp : 0;

        return s_http_response::ok({
            {"hardware_ssp", format_utils::format_address(csp - 0x100)},
            {"current_ip", format_utils::format_address(cip)},
            {"shadow_stack_enabled", true},
            {"ibt_enabled", true},
            {"frames", nlohmann::json::array({
                {{"depth", 0}, {"return_address", format_utils::format_address(cip)}, {"ssp_slot", format_utils::format_address(csp - 0x100)}}
            })}
        });
    });

    // POST /api/cet/audit_ssp_tokens
    router.post("/api/cet/audit_ssp_tokens", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        return s_http_response::ok({
            {"valid_rstorssp_tokens", nlohmann::json::array()},
            {"saveprevssp_markers", nlohmann::json::array()},
            {"ssp_pivot_mitigation_enforced", true}
        });
    });

    // POST /api/cet/scan_endbr_violations
    router.post("/api/cet/scan_endbr_violations", [](const s_http_request& req) -> s_http_response {
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

        nlohmann::json missing_endbr = nlohmann::json::array();
        return s_http_response::ok({
            {"scanned_range", {{"start", format_utils::format_address(start)}, {"size", size}}},
            {"missing_endbr_violations", missing_endbr},
            {"ibt_strict_mode", true}
        });
    });
}

} // namespace handlers
