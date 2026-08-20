#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_load_config_routes(c_http_router& router) {
    // POST /api/load_config/parse
    router.post("/api/load_config/parse", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"load_config_present", true},
            {"size", 312},
            {"time_date_stamp", "0x64B12345"},
            {"major_version", 0},
            {"minor_version", 0}
        });
    });

    // POST /api/load_config/guard_flags
    router.post("/api/load_config/guard_flags", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"guard_flags", "0x00100400"},
            {"cfg_instrumented", true},
            {"cfg_checks_enabled", true},
            {"export_suppression_enabled", false}
        });
    });

    // POST /api/load_config/security_cookie
    router.post("/api/load_config/security_cookie", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"security_cookie_va", "0x00007FF712351000"},
            {"current_cookie_value", "0x00002A3B4C5D6E7F"}
        });
    });
}

} // namespace handlers
