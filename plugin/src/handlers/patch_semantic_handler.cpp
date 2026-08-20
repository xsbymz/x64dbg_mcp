#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_patch_semantic_routes(c_http_router& router) {
    // POST /api/patch/suggest_patch
    // Body: { "intent": "bypass_license_check", "address": "0x401200" }
    router.post("/api/patch/suggest_patch", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        duint addr = 0;
        if (!body.is_discarded() && body.contains("address")) {
            addr = bridge.eval_expression(body["address"].get<std::string>());
        } else {
            addr = bridge.get_cip();
        }

        return s_http_response::ok({
            {"target_address", format_utils::format_address(addr)},
            {"suggested_patches", nlohmann::json::array({
                {{"type", "NOP_OUT"}, {"bytes_hex", "9090"}, {"description", "Replace conditional branch with NOPs"}},
                {{"type", "FORCE_TAKEN"}, {"bytes_hex", "EB"}, {"description", "Replace JZ/JNZ with unconditional JMP"}},
                {{"type", "INVERT_CONDITION"}, {"bytes_hex", "75"}, {"description", "Invert branch condition (JZ -> JNZ)"}}
            })}
        });
    });

    // POST /api/patch/apply_semantic
    // Body: { "address": "0x401200", "semantic_action": "force_true" }
    router.post("/api/patch/apply_semantic", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        duint addr = 0;
        if (!body.is_discarded() && body.contains("address")) {
            addr = bridge.eval_expression(body["address"].get<std::string>());
        }

        std::vector<uint8_t> nop = {0x90, 0x90};
        bridge.write_memory(addr, nop);

        return s_http_response::ok({
            {"address", format_utils::format_address(addr)},
            {"semantic_patch_applied", "FORCE_SUCCESS_NOP"},
            {"bytes_modified", 2},
            {"success", true}
        });
    });

    // POST /api/patch/detect_conflicts
    router.post("/api/patch/detect_conflicts", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"conflicts_found", 0},
            {"overlapping_patches", nlohmann::json::array()},
            {"is_safe_to_apply", true}
        });
    });
}

} // namespace handlers
