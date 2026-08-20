#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"
#include "util/input_sanitizer.h"
#include "util/path_sanitizer.h"
#include "http/auth.h"
#include "http/audit_logger.h"

#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_audit_routes(c_http_router& router) {
    router.get("/api/audit/log", [](const s_http_request& req) -> s_http_response {
        auto& audit = get_audit_logger();
        auto limit_str = req.get_query("limit", "100");
        int limit = format_utils::safe_parse_int(limit_str, 100);
        if (limit < 1) limit = 1;
        if (limit > 1000) limit = 1000;

        auto entries = audit.get_recent(limit);
        return s_http_response::ok({
            {"entries", entries},
            {"count", entries.size()}
        });
    });

    router.get("/api/audit/stats", [](const s_http_request&) -> s_http_response {
        auto& audit = get_audit_logger();
        auto stats = audit.get_stats();
        return s_http_response::ok(stats);
    });

    router.post("/api/audit/clear", [](const s_http_request&) -> s_http_response {
        auto& audit = get_audit_logger();
        audit.clear();
        return s_http_response::ok({
            {"cleared", true},
            {"message", "Audit log cleared"}
        });
    });
}

} // namespace handlers
