#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_pipe_sec_routes(c_http_router& router) {
    // GET /api/pipe_sec/audit
    router.get("/api/pipe_sec/audit", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"impersonation_apis_hooked", false},
            {"impersonate_named_pipe_client_calls", 0}
        });
    });

    // POST /api/pipe_sec/security_descriptor
    router.post("/api/pipe_sec/security_descriptor", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"owner_sid", "S-1-5-18 (NT AUTHORITY\\SYSTEM)"},
            {"dacl_present", true},
            {"everyone_has_write", false}
        });
    });

    // POST /api/pipe_sec/client_token
    router.post("/api/pipe_sec/client_token", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"impersonation_level", "SecurityImpersonation (2)"},
            {"elevation_vulnerable", false}
        });
    });
}

} // namespace handlers
