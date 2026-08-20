#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_str_obf_routes(c_http_router& router) {
    // POST /api/str_obf/stack_strings
    router.post("/api/str_obf/stack_strings", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"stack_strings_count", 1},
            {"strings", nlohmann::json::array({
                {{"constructed_string", "cmd.exe /c calc.exe"}, {"at_instruction", "0x00007FF712341020"}, {"length", 19}}
            })}
        });
    });

    // POST /api/str_obf/xor_tables
    router.post("/api/str_obf/xor_tables", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"xor_tables_found", 1},
            {"tables", nlohmann::json::array({
                {{"table_address", "0x00007FF712352000"}, {"estimated_key", "0x5A"}, {"strings_count", 8}}
            })}
        });
    });

    // POST /api/str_obf/function_strings
    router.post("/api/str_obf/function_strings", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"recovered_strings", nlohmann::json::array({
                "http://example.com/gate.php",
                "POST"
            })}
        });
    });
}

} // namespace handlers
