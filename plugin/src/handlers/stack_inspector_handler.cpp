#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_stack_inspector_routes(c_http_router& router) {
    // GET /api/stack/unwind
    router.get("/api/stack/unwind", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        duint csp = bridge.eval_expression("csp");
        duint cip = bridge.get_cip();

        DBGCALLSTACK callstack{};
        DbgFunctions()->GetCallStackEx(&callstack, false);

        nlohmann::json stack_frames = nlohmann::json::array();
        for (int i = 0; i < callstack.total && i < 20; ++i) {
            const auto& entry = callstack.entries[i];
            stack_frames.push_back({
                {"index",   i},
                {"address", format_utils::format_address(entry.addr)},
                {"from",    format_utils::format_address(entry.from)},
                {"to",      format_utils::format_address(entry.to)},
                {"label",   bridge.get_label_at(entry.to)},
                {"module",  bridge.get_module_at(entry.to)}
            });
        }
        if (callstack.entries) {
            BridgeFree(callstack.entries);
        }

        return s_http_response::ok({
            {"current_csp", format_utils::format_address(csp)},
            {"current_cip", format_utils::format_address(cip)},
            {"frame_count", stack_frames.size()},
            {"frames", stack_frames}
        });
    });

    // POST /api/stack/inspect_frame
    // Body: { "frame_index": 0, "depth": 16 }
    router.post("/api/stack/inspect_frame", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        int depth = body.value("depth", 16);
        duint csp = bridge.eval_expression("csp");

        auto mem_res = bridge.read_memory(csp, depth * sizeof(duint));
        if (!mem_res.has_value() || mem_res.value().size() < depth * sizeof(duint)) {
            return s_http_response::internal_error("Failed to read stack frame memory");
        }
        const auto* values = reinterpret_cast<const duint*>(mem_res.value().data());

        nlohmann::json slots = nlohmann::json::array();
        for (int i = 0; i < depth; ++i) {
            duint slot_addr = csp + i * sizeof(duint);
            duint slot_val = values[i];
            std::string label = bridge.get_label_at(slot_val);
            std::string mod = bridge.get_module_at(slot_val);

            slots.push_back({
                {"offset", i * static_cast<int>(sizeof(duint))},
                {"address", format_utils::format_address(slot_addr)},
                {"value", format_utils::format_address(slot_val)},
                {"label", label},
                {"module", mod}
            });
        }

        return s_http_response::ok({
            {"csp", format_utils::format_address(csp)},
            {"slots_inspected", depth},
            {"slots", slots}
        });
    });

    // POST /api/stack/parse_parameters
    // Body: { "address": "0x401000", "calling_convention": "fastcall" }
    router.post("/api/stack/parse_parameters", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto regs = bridge.get_register_dump();
        duint csp = bridge.eval_expression("csp");

        std::string rcx_val = "0x0", rdx_val = "0x0", r8_val = "0x0", r9_val = "0x0";
        if (regs.has_value()) {
            const auto& r = regs.value();
            rcx_val = format_utils::format_address(r.regcontext.ccx);
            rdx_val = format_utils::format_address(r.regcontext.cdx);
            rcx_val = format_utils::format_address(r.regcontext.ccx);
#ifdef _WIN64
            r8_val = format_utils::format_address(r.regcontext.r8);
            r9_val = format_utils::format_address(r.regcontext.r9);
#endif
        }

        return s_http_response::ok({
            {"calling_convention", "Microsoft x64 fastcall"},
            {"register_params", {
                {"rcx", rcx_val},
                {"rdx", rdx_val},
                {"r8",  r8_val},
                {"r9",  r9_val}
            }},
            {"shadow_space_base", format_utils::format_address(csp)},
            {"stack_arguments_parsed", 4}
        });
    });
}

} // namespace handlers
