#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_token_group_routes(c_http_router& router) {
    // GET /api/token_group/audit
    router.get("/api/token_group/audit", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"groups_count", 6},
            {"groups", nlohmann::json::array({
                {{"sid", "S-1-5-32-544"}, {"name", "BUILTIN\\Administrators"}, {"attributes", "SE_GROUP_ENABLED (0x04)"}}
            })}
        });
    });

    // GET /api/token_group/deny_only
    router.get("/api/token_group/deny_only", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"deny_only_sids_count", 0},
            {"sids", nlohmann::json::array()}
        });
    });

    // GET /api/token_group/integrity
    router.get("/api/token_group/integrity", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"integrity_sid", "S-1-16-12288"},
            {"integrity_level", "HIGH_INTEGRITY"}
        });
    });
}

} // namespace handlers
