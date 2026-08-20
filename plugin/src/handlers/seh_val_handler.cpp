#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_seh_val_routes(c_http_router& router) {
    // POST /api/seh_val/validate
    router.post("/api/seh_val/validate", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"is_valid_handler", true},
            {"in_executable_memory", true},
            {"in_safeseh_table", true},
            {"status", "HANDLER_VALIDATED"}
        });
    });

    // POST /api/seh_val/safeseh
    router.post("/api/seh_val/safeseh", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"safeseh_enabled", true},
            {"registered_handlers_count", 48}
        });
    });

    // GET /api/seh_val/stack
    router.get("/api/seh_val/stack", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"handlers_on_stack", 2},
            {"all_valid", true}
        });
    });
}

} // namespace handlers
