#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_ole_clip_routes(c_http_router& router) {
    // GET /api/ole_clip/formats
    router.get("/api/ole_clip/formats", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"formats_count", 3},
            {"formats", nlohmann::json::array({
                {{"id", 1}, {"name", "CF_TEXT"}},
                {{"id", 13}, {"name", "CF_UNICODETEXT"}}
            })}
        });
    });

    // POST /api/ole_clip/name
    router.post("/api/ole_clip/name", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"format_name", "CF_UNICODETEXT"}
        });
    });

    // POST /api/ole_clip/medium
    router.post("/api/ole_clip/medium", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"tymed", "TYMED_HGLOBAL (1)"},
            {"hGlobal", "0x0000000000251000"}
        });
    });
}

} // namespace handlers
