#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_exception_tester_routes(c_http_router& router) {
    // POST /api/exception_tester/simulate
    router.post("/api/exception_tester/simulate", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string code = body.value("exception_code", "0xC0000094");

        return s_http_response::ok({
            {"simulation_status", "EXCEPTION_DISPATCHED"},
            {"code", code},
            {"handled_by_debugger", true}
        });
    });

    // GET /api/exception_tester/codes
    router.get("/api/exception_tester/codes", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"common_exception_codes", nlohmann::json::array({
                {{"code", "0xC0000005"}, {"name", "EXCEPTION_ACCESS_VIOLATION"}},
                {{"code", "0xC0000094"}, {"name", "EXCEPTION_INT_DIVIDE_BY_ZERO"}},
                {{"code", "0x80000001"}, {"name", "EXCEPTION_GUARD_PAGE"}},
                {{"code", "0xC000001D"}, {"name", "EXCEPTION_ILLEGAL_INSTRUCTION"}},
                {{"code", "0xC0000096"}, {"name", "EXCEPTION_PRIV_INSTRUCTION"}}
            })}
        });
    });
}

} // namespace handlers
