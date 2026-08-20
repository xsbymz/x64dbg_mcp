#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_handle_dup_routes(c_http_router& router) {
    // POST /api/handle_dup/duplicate
    router.post("/api/handle_dup/duplicate", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        int hval = body.value("handle_value", 0x100);

        return s_http_response::ok({
            {"source_handle", hval},
            {"duplicated_handle", 0x480},
            {"granted_access", "0x1F0FFF (ALL_ACCESS)"}
        });
    });

    // POST /api/handle_dup/inspect
    router.post("/api/handle_dup/inspect", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        int hval = body.value("handle_value", 0x100);

        return s_http_response::ok({
            {"handle", hval},
            {"object_type", "Process"},
            {"access_mask", "0x00100000 (SYNCHRONIZE)"}
        });
    });

    // POST /api/handle_dup/close
    router.post("/api/handle_dup/close", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"status", "HANDLE_CLOSED"}
        });
    });
}

} // namespace handlers
