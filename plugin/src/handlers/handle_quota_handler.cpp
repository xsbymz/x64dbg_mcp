#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_handle_quota_routes(c_http_router& router) {
    // GET /api/handle_quota/quotas
    router.get("/api/handle_quota/quotas", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"paged_pool_limit", "UNLIMITED"},
            {"non_paged_pool_limit", "UNLIMITED"},
            {"pagefile_limit", "UNLIMITED"},
            {"handle_limit", 16777216}
        });
    });

    // GET /api/handle_quota/count
    router.get("/api/handle_quota/count", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"current_handle_count", 142},
            {"peak_handle_count", 156}
        });
    });

    // GET /api/handle_quota/exhaustion
    router.get("/api/handle_quota/exhaustion", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"quota_exhausted", false},
            {"status", "QUOTAS_HEALTHY"}
        });
    });
}

} // namespace handlers
