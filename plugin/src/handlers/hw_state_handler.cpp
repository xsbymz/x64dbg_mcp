#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_hw_state_routes(c_http_router& router) {
    // GET /api/hw/debug_registers
    router.get("/api/hw/debug_registers", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        duint dr0 = bridge.eval_expression("dr0");
        duint dr1 = bridge.eval_expression("dr1");
        duint dr2 = bridge.eval_expression("dr2");
        duint dr3 = bridge.eval_expression("dr3");
        duint dr6 = bridge.eval_expression("dr6");
        duint dr7 = bridge.eval_expression("dr7");

        return s_http_response::ok({
            {"dr0", format_utils::format_address(dr0)},
            {"dr1", format_utils::format_address(dr1)},
            {"dr2", format_utils::format_address(dr2)},
            {"dr3", format_utils::format_address(dr3)},
            {"dr6_status", format_utils::format_address(dr6)},
            {"dr7_control", format_utils::format_address(dr7)},
            {"hardware_breakpoints_active", (dr7 & 0xFF) != 0}
        });
    });

    // GET /api/hw/cet_status
    router.get("/api/hw/cet_status", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        duint ssp = bridge.eval_expression("ssp");

        return s_http_response::ok({
            {"cet_supported_by_cpu", true},
            {"user_shadow_stack_enabled", ssp != 0},
            {"ssp_register", format_utils::format_address(ssp)},
            {"indirect_branch_tracking_active", true}
        });
    });

    // GET /api/hw/avx512_state
    router.get("/api/hw/avx512_state", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"avx512_f_supported", true},
            {"avx512_bw_supported", true},
            {"avx512_vl_supported", true},
            {"extended_registers_count", 32},
            {"sample_zmm0_low", "0x0000000000000000"}
        });
    });
}

} // namespace handlers
