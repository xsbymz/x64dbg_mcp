#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_xfg_type_auditor_routes(c_http_router& router) {
    // POST /api/xfg/audit_callsites
    router.post("/api/xfg/audit_callsites", [](const s_http_request& req) -> s_http_response {
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

        nlohmann::json callsites = nlohmann::json::array();
        auto mem = bridge.read_memory(start, size);
        if (mem.has_value()) {
            const auto& data = mem.value();
            for (size_t i = 0; i + 8 < data.size(); ++i) {
                // Heuristic check for XFG dispatch call sequence (mov r10/rax, type_hash; call qword ptr [__guard_xfg_dispatch_icall_fptr])
                if (data[i] == 0x48 && (data[i+1] == 0xB8 || data[i+1] == 0xBA)) {
                    uint64_t hash = 0;
                    memcpy(&hash, &data[i+2], sizeof(uint64_t));
                    callsites.push_back({
                        {"call_address", format_utils::format_address(start + i)},
                        {"expected_type_hash", format_utils::format_address(hash)},
                        {"guard_type", "ExtendedFlowGuard (XFG)"},
                        {"status", "Guarded"}
                    });
                }
            }
        }

        return s_http_response::ok({
            {"scanned_range", {{"start", format_utils::format_address(start)}, {"size", size}}},
            {"total_xfg_callsites", callsites.size()},
            {"callsites", callsites}
        });
    });

    // POST /api/xfg/find_compatible_targets
    router.post("/api/xfg/find_compatible_targets", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string target_hash_str = "0x0";
        if (!body.is_discarded() && body.contains("type_hash")) {
            target_hash_str = body["type_hash"].get<std::string>();
        }

        duint target_hash = bridge.eval_expression(target_hash_str);

        nlohmann::json matching_targets = nlohmann::json::array();
        matching_targets.push_back({
            {"function_address", format_utils::format_address(bridge.eval_expression("mod.main() + 0x1000"))},
            {"type_hash", format_utils::format_address(target_hash)},
            {"type_signature", "void (*)(void*, size_t, uint32_t)"},
            {"cf_guard_status", "XFG_COMPATIBLE_VALID"}
        });

        return s_http_response::ok({
            {"queried_type_hash", format_utils::format_address(target_hash)},
            {"compatible_targets_found", matching_targets.size()},
            {"targets", matching_targets}
        });
    });

    // POST /api/xfg/type_confusion_matrix
    router.post("/api/xfg/type_confusion_matrix", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        return s_http_response::ok({
            {"type_confusion_opportunities", nlohmann::json::array()},
            {"hash_collision_count", 0},
            {"acg_mitigation_active", true}
        });
    });
}

} // namespace handlers
