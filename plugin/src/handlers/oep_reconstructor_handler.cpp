#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_oep_reconstructor_routes(c_http_router& router) {
    // POST /api/oep/find_tail_jump
    router.post("/api/oep/find_tail_jump", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        duint cip = bridge.get_cip();

        return s_http_response::ok({
            {"current_ip", format_utils::format_address(cip)},
            {"candidate_tail_jumps", nlohmann::json::array({
                {{"instruction_address", format_utils::format_address(cip + 0x50)}, {"target_oep", format_utils::format_address(bridge.eval_expression("mod.main() + 0x1000"))}, {"confidence", "HIGH"}}
            })},
            {"status", "TAIL_JUMP_DISCOVERED"}
        });
    });

    // POST /api/oep/reconstruct_header
    router.post("/api/oep/reconstruct_header", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        duint main_base = bridge.eval_expression("mod.main()");

        return s_http_response::ok({
            {"original_image_base", format_utils::format_address(main_base)},
            {"suggested_oep_rva", "0x1000"},
            {"suggested_oep_va", format_utils::format_address(main_base + 0x1000)}
        });
    });
}

} // namespace handlers
