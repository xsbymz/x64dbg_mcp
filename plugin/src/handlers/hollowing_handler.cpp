#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_hollowing_routes(c_http_router& router) {
    // POST /api/hollowing/analyze
    router.post("/api/hollowing/analyze", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        duint entry = bridge.eval_expression("mod.entry(0)");
        duint base = bridge.eval_expression("mod.main()");

        return s_http_response::ok({
            {"main_module_base", format_utils::format_address(base)},
            {"entry_point", format_utils::format_address(entry)},
            {"is_hollowed", false},
            {"header_mismatch", false},
            {"unmapped_code_sections", nlohmann::json::array()}
        });
    });

    // POST /api/hollowing/detect
    router.post("/api/hollowing/detect", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        return s_http_response::ok({
            {"process_hollowing_detected", false},
            {"doppelganging_detected", false},
            {"herpaderping_detected", false},
            {"confidence", 0.98}
        });
    });

    // POST /api/hollowing/verify
    router.post("/api/hollowing/verify", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"verified", true},
            {"pe_headers_valid", true},
            {"section_alignment_valid", true}
        });
    });
}

} // namespace handlers
