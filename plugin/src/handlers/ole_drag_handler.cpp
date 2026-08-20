#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_ole_drag_routes(c_http_router& router) {
    // GET /api/ole_drag/targets
    router.get("/api/ole_drag/targets", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"registered_drop_targets_count", 1},
            {"drop_targets", nlohmann::json::array({
                {{"hwnd", "0x00010120"}, {"idroptarget_vtable", "0x00007FFB82352000"}}
            })}
        });
    });

    // GET /api/ole_drag/formats
    router.get("/api/ole_drag/formats", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"supported_clip_formats", nlohmann::json::array({"CF_HDROP", "CF_TEXT", "FileGroupDescriptor"})}
        });
    });

    // GET /api/ole_drag/buffer
    router.get("/api/ole_drag/buffer", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"is_drag_active", false},
            {"buffer_bytes_cached", 0}
        });
    });
}

} // namespace handlers
