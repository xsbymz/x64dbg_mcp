#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_appcontainer_cap_routes(c_http_router& router) {
    // GET /api/appcontainer_cap/check
    router.get("/api/appcontainer_cap/check", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"has_internet_client", true},
            {"has_private_network", false},
            {"has_documents_library", false}
        });
    });

    // GET /api/appcontainer_cap/sids
    router.get("/api/appcontainer_cap/sids", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"capabilities", nlohmann::json::array({
                {{"name", "internetClient"}, {"sid", "S-1-15-3-1"}}
            })}
        });
    });

    // GET /api/appcontainer_cap/boundary
    router.get("/api/appcontainer_cap/boundary", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"isolation_type", "APPCONTAINER_LOWBOX"},
            {"boundary_integrity", "SECURE"}
        });
    });
}

} // namespace handlers
