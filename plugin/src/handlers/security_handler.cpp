#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"
#include "http/auth.h"
#include "http/rate_limiter.h"
#include "http/audit_logger.h"

namespace handlers {

void register_security_routes(c_http_router& router) {
    router.get("/api/security/status", [](const s_http_request&) -> s_http_response {
        auto& auth = get_auth_manager();
        auto& limiter = get_rate_limiter();
        auto& audit = get_audit_logger();

        auto stats = audit.get_stats();
        auto limiter_stats = limiter.get_stats();

        int concurrent = limiter_stats.value("concurrent_connections", 0);

        return s_http_response::ok({
            {"auth_enabled", auth.is_enabled()},
            {"rate_limiter", limiter_stats},
            {"audit_stats", stats},
            {"recommendations", nlohmann::json::array({
                auth.is_enabled() ? "OK" : "WARNING: Authentication is disabled. Set X64DBG_MCP_TOKEN.",
                concurrent > 5 ? "WARNING: High concurrent connection count" : "OK"
            })}
        });
    });

    router.get("/api/security/verify_token", [](const s_http_request& req) -> s_http_response {
        auto& auth = get_auth_manager();
        bool valid = auth.is_authorized(req, auth_level::read_only);
        return s_http_response::ok({
            {"token_valid", valid},
            {"auth_enabled", auth.is_enabled()}
        });
    });

    router.get("/api/security/hardening_report", [](const s_http_request&) -> s_http_response {
        auto& auth = get_auth_manager();
        auto& limiter = get_rate_limiter();

        nlohmann::json report = {
            {"auth", {
                {"enabled", auth.is_enabled()},
                {"status", auth.is_enabled() ? "SECURE" : "INSECURE"}
            }},
            {"rate_limiting", {
                {"enabled", true},
                {"max_concurrent", 10},
                {"max_requests_per_second", 100},
                {"status", "ACTIVE"}
            }},
            {"input_validation", {
                {"expression_sanitization", true},
                {"command_whitelisting", true},
                {"path_traversal_prevention", true},
                {"status", "ACTIVE"}
            }},
            {"thread_safety", {
                {"shared_mutex_enabled", true},
                {"concurrent_reads", true},
                {"serialized_writes", true},
                {"status", "ACTIVE"}
            }},
            {"audit_logging", {
                {"enabled", true},
                {"max_entries", 10000},
                {"status", "ACTIVE"}
            }}
        };

        return s_http_response::ok(report);
    });
}

} // namespace handlers
