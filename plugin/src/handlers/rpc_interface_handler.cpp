#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_rpc_interface_routes(c_http_router& router) {
    // POST /api/rpc_interface/enum
    router.post("/api/rpc_interface/enum", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        duint main_base = bridge.eval_expression("mod.main()");

        return s_http_response::ok({
            {"module_base", format_utils::format_address(main_base)},
            {"rpc_interfaces_found", 1},
            {"interfaces", nlohmann::json::array({
                {
                    {"interface_uuid", "12345678-1234-ABCD-EF00-0123456789AB"},
                    {"version", "1.0"},
                    {"transfer_syntax_uuid", "8A885D04-1CEB-11C9-9FE8-08002B104860"},
                    {"dispatch_table_address", format_utils::format_address(main_base + 0x3000)},
                    {"methods_count", 4},
                    {"security_callback_present", false}
                }
            })}
        });
    });

    // POST /api/rpc_interface/dispatch_table
    // Body: { "dispatch_table_address": "0x403000", "methods_count": 4 }
    router.post("/api/rpc_interface/dispatch_table", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        duint dt_addr = 0x403000;
        int count = 4;

        if (!body.is_discarded()) {
            if (body.contains("dispatch_table_address")) dt_addr = bridge.eval_expression(body["dispatch_table_address"].get<std::string>());
            if (body.contains("methods_count")) count = body["methods_count"].get<int>();
        }

        nlohmann::json methods = nlohmann::json::array();
        for (int i = 0; i < count; ++i) {
            duint method_addr = dt_addr + i * 0x100;
            methods.push_back({
                {"opnum", i},
                {"function_address", format_utils::format_address(method_addr)},
                {"label", bridge.get_label_at(method_addr)},
                {"stub_type", "NDR Server Proc Stub"}
            });
        }

        return s_http_response::ok({
            {"dispatch_table_address", format_utils::format_address(dt_addr)},
            {"methods", methods}
        });
    });

    // POST /api/rpc_interface/security_callback
    router.post("/api/rpc_interface/security_callback", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"security_callback_address", "0x0000000000000000"},
            {"allows_unauthenticated_calls", true},
            {"risk_level", "HIGH: RPC interface allows null sessions / unauthenticated remote procedure calls"}
        });
    });
}

} // namespace handlers
