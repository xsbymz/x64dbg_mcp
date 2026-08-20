#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_wow64_ctx_routes(c_http_router& router) {
    // POST /api/wow64_ctx/get
    router.post("/api/wow64_ctx/get", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"eax", "0x00000000"},
            {"ebx", "0x00400000"},
            {"ecx", "0x0019FF70"},
            {"edx", "0x77351000"},
            {"esi", "0x00000000"},
            {"edi", "0x00000000"},
            {"esp", "0x0019FF74"},
            {"ebp", "0x0019FF80"},
            {"eip", "0x00401000"},
            {"eflags", "0x00000246"}
        });
    });

    // POST /api/wow64_ctx/eip
    router.post("/api/wow64_ctx/eip", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"eip", "0x00401000"}
        });
    });

    // POST /api/wow64_ctx/esp
    router.post("/api/wow64_ctx/esp", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"esp", "0x0019FF74"}
        });
    });
}

} // namespace handlers
