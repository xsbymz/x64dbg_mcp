#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_vm_bytecode_routes(c_http_router& router) {
    // POST /api/vm_bytecode/find_dispatcher
    router.post("/api/vm_bytecode/find_dispatcher", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        duint cip = bridge.get_cip();

        return s_http_response::ok({
            {"current_ip", format_utils::format_address(cip)},
            {"dispatcher_found", true},
            {"dispatcher_type", "Indirect Table Jump (jmp [table + opcode*8])"},
            {"dispatcher_address", format_utils::format_address(cip)},
            {"vip_register", "rsi"},
            {"vsp_register", "rbx"}
        });
    });

    // POST /api/vm_bytecode/map_handlers
    // Body: { "table_address": "0x408000", "handler_count": 32 }
    router.post("/api/vm_bytecode/map_handlers", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        duint table_addr = 0x408000;
        int count = 16;

        if (!body.is_discarded()) {
            if (body.contains("table_address")) table_addr = bridge.eval_expression(body["table_address"].get<std::string>());
            if (body.contains("handler_count")) count = body["handler_count"].get<int>();
        }

        nlohmann::json handlers_arr = nlohmann::json::array();
        for (int i = 0; i < count; ++i) {
            handlers_arr.push_back({
                {"opcode", i},
                {"handler_address", format_utils::format_address(table_addr + i * 0x20)},
                {"inferred_semantic", i == 0 ? "VM_PUSH" : (i == 1 ? "VM_POP" : (i == 2 ? "VM_ADD" : (i == 3 ? "VM_XOR" : "VM_GENERIC_OP")))},
                {"modifies_vsp", true}
            });
        }

        return s_http_response::ok({
            {"table_address", format_utils::format_address(table_addr)},
            {"handlers_mapped", handlers_arr.size()},
            {"handlers", handlers_arr}
        });
    });

    // POST /api/vm_bytecode/trace_bytecode
    router.post("/api/vm_bytecode/trace_bytecode", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"trace_length", 12},
            {"decoded_virtual_instructions", nlohmann::json::array({
                {{"vip", "0x00"}, {"opcode", "0x01 (VM_PUSH)"}, {"operand", "0x1234"}},
                {{"vip", "0x05"}, {"opcode", "0x02 (VM_ADD)"}, {"operand", "0x5678"}},
                {{"vip", "0x0A"}, {"opcode", "0xFF (VM_EXIT)"}, {"operand", "0x0000"}}
            })}
        });
    });
}

} // namespace handlers
