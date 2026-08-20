#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_loopback_check_routes(c_http_router& router) {
    // POST /api/loopback_check/check
    router.post("/api/loopback_check/check", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"loopback_exempt", false},
            {"status", "LOOPBACK_BLOCKED"}
        });
    });

    // GET /api/loopback_check/list
    router.get("/api/loopback_check/list", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"exempt_containers_count", 0},
            {"containers", nlohmann::json::array()}
        });
    });

    // POST /api/loopback_check/flags
    router.post("/api/loopback_check/flags", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"network_isolation_flags", "NETISO_FLAG_FORCE_COMPUTE_BINARIES (0x01)"}
        });
    });
}

} // namespace handlers
