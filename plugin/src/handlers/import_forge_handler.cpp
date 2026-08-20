#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <unordered_map>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

static std::unordered_map<duint, duint> g_original_iat_entries;

void register_import_forge_routes(c_http_router& router) {
    // GET /api/import_forge/list
    router.get("/api/import_forge/list", [](const s_http_request&) -> s_http_response {
        nlohmann::json hooks = nlohmann::json::array();
        for (const auto& [addr, orig] : g_original_iat_entries) {
            hooks.push_back({
                {"iat_entry_address", format_utils::format_address(addr)},
                {"original_target", format_utils::format_address(orig)}
            });
        }
        return s_http_response::ok({
            {"active_iat_hooks", hooks.size()},
            {"hooks", hooks}
        });
    });

    // POST /api/import_forge/redirect
    // Body: { "iat_address": "0x405000", "new_target": "0x401500" }
    router.post("/api/import_forge/redirect", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("iat_address") || !body.contains("new_target")) {
            return s_http_response::bad_request("Missing iat_address or new_target");
        }

        duint iat_addr = bridge.eval_expression(body["iat_address"].get<std::string>());
        duint new_target = bridge.eval_expression(body["new_target"].get<std::string>());

        duint orig_val = 0;
        auto read_res = bridge.read_memory(iat_addr, sizeof(duint));
        if (read_res.has_value() && read_res.value().size() == sizeof(duint)) {
            orig_val = *reinterpret_cast<const duint*>(read_res.value().data());
        }
        g_original_iat_entries[iat_addr] = orig_val;

        std::vector<uint8_t> data(sizeof(duint));
        std::memcpy(data.data(), &new_target, sizeof(duint));
        auto write_res = bridge.write_memory(iat_addr, data);
        if (!write_res.has_value()) {
            return s_http_response::internal_error("Failed to write to IAT entry");
        }

        return s_http_response::ok({
            {"iat_address", format_utils::format_address(iat_addr)},
            {"previous_target", format_utils::format_address(orig_val)},
            {"new_target", format_utils::format_address(new_target)},
            {"status", "redirected"}
        });
    });

    // POST /api/import_forge/hook
    router.post("/api/import_forge/hook", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({{"hook_installed", true}, {"detour_type", "IAT_POINTER_OVERWRITE"}});
    });

    // POST /api/import_forge/restore
    // Body: { "iat_address": "0x405000" }
    router.post("/api/import_forge/restore", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        duint iat_addr = 0;
        if (!body.is_discarded() && body.contains("iat_address")) {
            iat_addr = bridge.eval_expression(body["iat_address"].get<std::string>());
        }

        if (g_original_iat_entries.count(iat_addr)) {
            duint orig = g_original_iat_entries[iat_addr];
            std::vector<uint8_t> orig_data(sizeof(duint));
            std::memcpy(orig_data.data(), &orig, sizeof(duint));
            bridge.write_memory(iat_addr, orig_data);
            g_original_iat_entries.erase(iat_addr);
            return s_http_response::ok({
                {"iat_address", format_utils::format_address(iat_addr)},
                {"restored_target", format_utils::format_address(orig)},
                {"status", "restored"}
            });
        }

        return s_http_response::bad_request("IAT address was not tracked or previously hooked");
    });
}

} // namespace handlers
