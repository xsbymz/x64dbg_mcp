#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_wow64_fs_routes(c_http_router& router) {
    // GET /api/wow64_fs/state
    router.get("/api/wow64_fs/state", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"fs_redirection_disabled", false},
            {"is_wow64_process", false}
        });
    });

    // POST /api/wow64_fs/simulate
    router.post("/api/wow64_fs/simulate", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string p = body.value("path", "C:\\Windows\\System32\\cmd.exe");

        return s_http_response::ok({
            {"input_path", p},
            {"redirected_path", "C:\\Windows\\SysWOW64\\cmd.exe"},
            {"would_be_redirected", true}
        });
    });

    // GET /api/wow64_fs/directories
    router.get("/api/wow64_fs/directories", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"redirected_directories", nlohmann::json::array({"%windir%\\system32", "%windir%\\sysnative"})}
        });
    });
}

} // namespace handlers
