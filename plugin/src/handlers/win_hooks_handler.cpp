#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_win_hooks_routes(c_http_router& router) {
    // GET /api/win_hooks/list
    router.get("/api/win_hooks/list", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"installed_hooks_count", 0},
            {"hooks", nlohmann::json::array()}
        });
    });

    // GET /api/win_hooks/keyloggers
    router.get("/api/win_hooks/keyloggers", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"low_level_keyboard_hooks_detected", false},
            {"low_level_mouse_hooks_detected", false}
        });
    });

    // GET /api/win_hooks/modules
    router.get("/api/win_hooks/modules", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"hook_dlls_count", 0}
        });
    });
}

} // namespace handlers
