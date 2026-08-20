#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_token_privilege_routes(c_http_router& router) {
    // GET /api/token/process
    router.get("/api/token/process", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"token_type", "TokenPrimary"},
            {"integrity_level", "Medium Integrity (S-1-16-8192)"},
            {"elevation_type", "TokenElevationTypeDefault"},
            {"user_sid", "S-1-5-21-1234567890-1234567890-1234567890-1001"},
            {"is_elevated", false}
        });
    });

    // GET /api/token/thread
    router.get("/api/token/thread", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"is_impersonating", false},
            {"impersonation_level", "SecurityAnonymous"}
        });
    });

    // GET /api/token/privileges
    router.get("/api/token/privileges", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"privileges_count", 4},
            {"privileges", nlohmann::json::array({
                {{"name", "SeShutdownPrivilege"}, {"status", "DISABLED"}, {"attributes", "0x00000000"}},
                {{"name", "SeChangeNotifyPrivilege"}, {"status", "ENABLED_BY_DEFAULT"}, {"attributes", "0x00000003"}},
                {{"name", "SeUndockPrivilege"}, {"status", "DISABLED"}, {"attributes", "0x00000000"}},
                {{"name", "SeIncreaseWorkingSetPrivilege"}, {"status", "DISABLED"}, {"attributes", "0x00000000"}}
            })}
        });
    });

    // GET /api/token/escalation_check
    router.get("/api/token/escalation_check", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"dangerous_privileges_enabled", false},
            {"sedebug_enabled", false},
            {"seimpersonate_enabled", false},
            {"risk_rating", "LOW"}
        });
    });
}

} // namespace handlers
