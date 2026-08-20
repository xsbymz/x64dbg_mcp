#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_font_carve_routes(c_http_router& router) {
    // GET /api/font_carve/scan
    router.get("/api/font_carve/scan", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"embedded_fonts_found", 0},
            {"fonts", nlohmann::json::array()}
        });
    });

    // POST /api/font_carve/header
    router.post("/api/font_carve/header", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"sfnt_version", "0x00010000 (TrueType)"},
            {"num_tables", 12}
        });
    });

    // POST /api/font_carve/table
    router.post("/api/font_carve/table", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"tables", nlohmann::json::array({"cmap", "glyf", "head", "hhea", "hmtx", "loca", "maxp", "name"})}
        });
    });
}

} // namespace handlers
