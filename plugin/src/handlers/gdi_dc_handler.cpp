#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_gdi_dc_routes(c_http_router& router) {
    // POST /api/gdi_dc/inspect
    router.post("/api/gdi_dc/inspect", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"map_mode", "MM_TEXT (1)"},
            {"bk_color", "0x00FFFFFF"},
            {"text_color", "0x00000000"}
        });
    });

    // POST /api/gdi_dc/objects
    router.post("/api/gdi_dc/objects", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"selected_font", "0x00000000010A1050"},
            {"selected_pen", "0x00000000020A1050"},
            {"selected_brush", "0x00000000030A1050"}
        });
    });

    // POST /api/gdi_dc/clipping
    router.post("/api/gdi_dc/clipping", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"has_clip_region", false},
            {"bounds", {{"left", 0}, {"top", 0}, {"right", 1920}, {"bottom", 1080}}}
        });
    });
}

} // namespace handlers
