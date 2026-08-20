#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_gdi_user_routes(c_http_router& router) {
    // GET /api/gdi_user/user_objects
    router.get("/api/gdi_user/user_objects", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"user_objects_count", 18},
            {"windows_count", 4},
            {"menus_count", 2},
            {"hooks_count", 0}
        });
    });

    // GET /api/gdi_user/gdi_objects
    router.get("/api/gdi_user/gdi_objects", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"gdi_objects_count", 42},
            {"bitmaps_count", 12},
            {"device_contexts_count", 6},
            {"fonts_count", 8},
            {"brushes_count", 10}
        });
    });

    // GET /api/gdi_user/limits
    router.get("/api/gdi_user/limits", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"gdi_limit_per_process", 10000},
            {"gdi_current_usage", 42},
            {"user_limit_per_process", 10000},
            {"user_current_usage", 18},
            {"exhaustion_risk", "LOW"}
        });
    });

    // GET /api/gdi_user/diff
    router.get("/api/gdi_user/diff", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"net_gdi_delta", 0},
            {"net_user_delta", 0}
        });
    });
}

} // namespace handlers
