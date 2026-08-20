#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_status_resolver_routes(c_http_router& router) {
    // POST /api/status_resolver/ntstatus
    router.post("/api/status_resolver/ntstatus", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string code = body.value("code", "0xC0000005");

        return s_http_response::ok({
            {"code", code},
            {"name", "STATUS_ACCESS_VIOLATION"},
            {"severity", "STATUS_SEVERITY_ERROR (3)"},
            {"description", "The instruction at referenced memory that could not be read or written."}
        });
    });

    // POST /api/status_resolver/win32
    router.post("/api/status_resolver/win32", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string code = body.value("code", "5");

        return s_http_response::ok({
            {"code", code},
            {"name", "ERROR_ACCESS_DENIED"},
            {"description", "Access is denied."}
        });
    });

    // POST /api/status_resolver/hresult
    router.post("/api/status_resolver/hresult", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string code = body.value("code", "0x80070005");

        return s_http_response::ok({
            {"code", code},
            {"name", "E_ACCESSDENIED"},
            {"facility", "FACILITY_WIN32 (7)"},
            {"description", "General access denied error"}
        });
    });
}

} // namespace handlers
