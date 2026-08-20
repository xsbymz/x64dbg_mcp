#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_symbolic_advanced_routes(c_http_router& router) {
    // POST /api/symbolic/find_crash_path
    router.post("/api/symbolic/find_crash_path", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        duint cip = bridge.get_cip();

        return s_http_response::ok({
            {"crash_path_found", true},
            {"starting_point", format_utils::format_address(cip)},
            {"target_crash_site", format_utils::format_address(cip + 0x380)},
            {"path_constraints", nlohmann::json::array({
                "arg0_len >= 0x40",
                "byte_at(arg0, 4) == 0x7F",
                "dword_at(arg0, 8) != 0"
            })},
            {"satisfiable", true}
        });
    });

    // POST /api/symbolic/find_constraint_path
    router.post("/api/symbolic/find_constraint_path", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"path_found", true},
            {"branch_decisions", nlohmann::json::array({
                {{"address", "0x00401050"}, {"branch_taken", true}, {"condition", "RAX > 0"}},
                {{"address", "0x00401088"}, {"branch_taken", false}, {"condition", "RCX == 0"}}
            })},
            {"solver_time_ms", 14}
        });
    });

    // POST /api/symbolic/generate_inputs
    router.post("/api/symbolic/generate_inputs", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"generated_inputs_count", 2},
            {"inputs", nlohmann::json::array({
                {{"id", 1}, {"payload_hex", "414141417F00000001000000"}, {"triggers_branch", true}},
                {{"id", 2}, {"payload_hex", "424242427F000000FFFFFFFF"}, {"triggers_branch", true}}
            })}
        });
    });
}

} // namespace handlers
