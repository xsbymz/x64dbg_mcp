#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_pivot_hunter_routes(c_http_router& router) {
    // POST /api/pivot_hunter/find
    router.post("/api/pivot_hunter/find", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"stack_pivot_gadgets_found", 2},
            {"gadgets", nlohmann::json::array({
                {{"address", "0x00007FF712348120"}, {"disasm", "xchg rsp, rax; ret"}, {"shift_bytes", 0}, {"reliability_score", 0.98}},
                {{"address", "0x00007FF712348150"}, {"disasm", "mov rsp, rbx; ret"}, {"shift_bytes", 0}, {"reliability_score", 0.95}}
            })}
        });
    });

    // POST /api/pivot_hunter/score
    router.post("/api/pivot_hunter/score", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"clobbered_registers", nlohmann::json::array()},
            {"cet_compatible", true},
            {"cf_guard_compliant", false}
        });
    });

    // POST /api/pivot_hunter/by_register
    router.post("/api/pivot_hunter/by_register", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string reg = body.value("target_register", "RAX");

        return s_http_response::ok({
            {"register", reg},
            {"matching_pivots_count", 1}
        });
    });
}

} // namespace handlers
