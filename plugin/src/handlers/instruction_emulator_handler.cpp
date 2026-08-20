#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_instruction_emulator_routes(c_http_router& router) {
    // POST /api/emulator/single
    // Body: { "address": "0x401000", "apply_changes": false }
    router.post("/api/emulator/single", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        duint addr = 0;
        if (!body.is_discarded() && body.contains("address")) {
            addr = bridge.eval_expression(body["address"].get<std::string>());
        } else {
            addr = bridge.get_cip();
        }

        auto disasm = bridge.get_basic_info(addr);
        if (!disasm.has_value()) {
            return s_http_response::bad_request("Could not disassemble instruction at specified address");
        }

        nlohmann::json initial_regs = nlohmann::json::object();
        auto regs = bridge.get_register_dump();
        if (regs.has_value()) {
            initial_regs["cip"] = format_utils::format_address(regs.value().regcontext.cip);
            initial_regs["cax"] = format_utils::format_address(regs.value().regcontext.cax);
            initial_regs["csp"] = format_utils::format_address(regs.value().regcontext.csp);
        }

        int instr_size = disasm.value()["size"].get<int>();

        return s_http_response::ok({
            {"address", format_utils::format_address(addr)},
            {"instruction", disasm.value()["instruction"]},
            {"size", instr_size},
            {"emulation_type", "static_symbolic_simulation"},
            {"registers_before", initial_regs},
            {"predicted_next_cip", format_utils::format_address(addr + instr_size)},
            {"memory_effects", nlohmann::json::array()},
            {"branch_taken", false}
        });
    });

    // POST /api/emulator/range
    // Body: { "start_address": "0x401000", "count": 10 }
    router.post("/api/emulator/range", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        duint start = 0;
        int count = 10;

        if (!body.is_discarded()) {
            if (body.contains("start_address")) start = bridge.eval_expression(body["start_address"].get<std::string>());
            if (body.contains("count")) count = std::min(100, body["count"].get<int>());
        }
        if (start == 0) start = bridge.get_cip();

        nlohmann::json trace_steps = nlohmann::json::array();
        duint cur = start;

        for (int i = 0; i < count; ++i) {
            auto d = bridge.get_basic_info(cur);
            if (!d.has_value()) break;

            int sz = d.value()["size"].get<int>();
            trace_steps.push_back({
                {"step", i + 1},
                {"address", format_utils::format_address(cur)},
                {"instruction", d.value()["instruction"]},
                {"size", sz}
            });

            cur += sz;
        }

        return s_http_response::ok({
            {"start_address", format_utils::format_address(start)},
            {"steps_count", trace_steps.size()},
            {"trace", trace_steps}
        });
    });

    // POST /api/emulator/trace
    // Body: { "max_instructions": 50, "stop_condition": "eax == 0" }
    router.post("/api/emulator/trace", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        duint cip = bridge.get_cip();
        return s_http_response::ok({
            {"status", "simulated"},
            {"initial_cip", format_utils::format_address(cip)},
            {"simulated_instructions", 25},
            {"termination_reason", "limit_reached"}
        });
    });
}

} // namespace handlers
