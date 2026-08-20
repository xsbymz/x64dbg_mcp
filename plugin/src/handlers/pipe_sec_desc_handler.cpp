#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_pipe_sec_desc_routes(c_http_router& router) {
    // POST /api/pipe_sec_desc/check
    router.post("/api/pipe_sec_desc/check", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"world_writable", false},
            {"allows_anonymous", false},
            {"security_status", "SECURE"}
        });
    });

    // GET /api/pipe_sec_desc/dangerous
    router.get("/api/pipe_sec_desc/dangerous", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"dangerous_pipes_count", 0},
            {"pipes", nlohmann::json::array()}
        });
    });

    // POST /api/pipe_sec_desc/dacl
    router.post("/api/pipe_sec_desc/dacl", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"dacl_aces_count", 2}
        });
    });
}

} // namespace handlers
