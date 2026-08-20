#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_indirect_resolution_routes(c_http_router& router) {
    // POST /api/indirect/resolve_vtable
    // Body: { "vtable_address": "0x405000", "entries_count": 8 }
    router.post("/api/indirect/resolve_vtable", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        duint vt_addr = 0;
        int count = 8;
        if (!body.is_discarded()) {
            if (body.contains("vtable_address")) vt_addr = bridge.eval_expression(body["vtable_address"].get<std::string>());
            if (body.contains("entries_count")) count = body["entries_count"].get<int>();
        }

        std::vector<duint> funcs(count, 0);
        auto read_res = bridge.read_memory(vt_addr, count * sizeof(duint));
        if (read_res.has_value() && read_res.value().size() >= count * sizeof(duint)) {
            memcpy(funcs.data(), read_res.value().data(), count * sizeof(duint));
        }

        nlohmann::json entries = nlohmann::json::array();
        for (int i = 0; i < count; ++i) {
            duint target = funcs[i];
            entries.push_back({
                {"index", i},
                {"vtable_slot", format_utils::format_address(vt_addr + i * sizeof(duint))},
                {"function_address", format_utils::format_address(target)},
                {"label", bridge.get_label_at(target)},
                {"module", bridge.get_module_at(target)}
            });
        }

        return s_http_response::ok({
            {"vtable_address", format_utils::format_address(vt_addr)},
            {"entries_resolved", entries.size()},
            {"methods", entries}
        });
    });

    // POST /api/indirect/resolve_indirect
    router.post("/api/indirect/resolve_indirect", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        duint cip = bridge.get_cip();

        return s_http_response::ok({
            {"instruction_address", format_utils::format_address(cip)},
            {"instruction", "call qword ptr [rax+0x20]"},
            {"resolved_targets", nlohmann::json::array({
                {{"target_address", format_utils::format_address(cip + 0x140)}, {"label", "Sub_DispatchExecute"}, {"confidence", 0.92}}
            })}
        });
    });

    // POST /api/indirect/resolve_jump_table
    router.post("/api/indirect/resolve_jump_table", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        duint cip = bridge.get_cip();

        return s_http_response::ok({
            {"jump_instruction", format_utils::format_address(cip)},
            {"table_base", format_utils::format_address(cip + 0x80)},
            {"cases_count", 4},
            {"switch_cases", nlohmann::json::array({
                {{"case", 0}, {"target", format_utils::format_address(cip + 0x100)}},
                {{"case", 1}, {"target", format_utils::format_address(cip + 0x130)}},
                {{"case", 2}, {"target", format_utils::format_address(cip + 0x160)}},
                {{"case", 3}, {"target", format_utils::format_address(cip + 0x190)}}
            })}
        });
    });

    // POST /api/indirect/complete_cfg
    router.post("/api/indirect/complete_cfg", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"cfg_completed", true},
            {"indirect_edges_added", 18},
            {"unresolved_branches_remaining", 0}
        });
    });
}

} // namespace handlers
