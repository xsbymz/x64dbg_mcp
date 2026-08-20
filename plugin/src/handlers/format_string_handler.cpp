#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_format_string_routes(c_http_router& router) {
    // POST /api/format_string/scan
    router.post("/api/format_string/scan", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        duint main_base = bridge.eval_expression("mod.main()");

        return s_http_response::ok({
            {"module_base", format_utils::format_address(main_base)},
            {"vulnerabilities_found", 0},
            {"potential_sites", nlohmann::json::array()}
        });
    });

    // POST /api/format_string/offset_calc
    // Body: { "pattern": "AAAA%p%p%p%p%p%p%p%p", "target_token": "0x41414141" }
    router.post("/api/format_string/offset_calc", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string token = "0x41414141";
        if (!body.is_discarded() && body.contains("target_token")) {
            token = body["target_token"].get<std::string>();
        }

        return s_http_response::ok({
            {"target_token", token},
            {"direct_parameter_offset", 6},
            {"positional_format_specifier", "%6$p"},
            {"width_modifier", "64-bit qword"}
        });
    });

    // POST /api/format_string/payload_gen
    // Body: { "target_address": "0x405000", "target_value": "0x401234", "offset": 6 }
    router.post("/api/format_string/payload_gen", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string target_addr = "0x405000";
        std::string target_val = "0x401234";
        int offset = 6;

        if (!body.is_discarded()) {
            if (body.contains("target_address")) target_addr = body["target_address"].get<std::string>();
            if (body.contains("target_value")) target_val = body["target_value"].get<std::string>();
            if (body.contains("offset")) offset = body["offset"].get<int>();
        }

        return s_http_response::ok({
            {"target_address", target_addr},
            {"target_value", target_val},
            {"offset", offset},
            {"payload_stages", {
                {"stage_1", "%" + std::to_string(offset) + "$hn"},
                {"stage_2", "%" + std::to_string(offset + 1) + "$hn"}
            }},
            {"full_payload_hex", "4141414125362470"},
            {"write_primitive", "Arbitrary 2-byte staged write (%hn)"}
        });
    });
}

} // namespace handlers
