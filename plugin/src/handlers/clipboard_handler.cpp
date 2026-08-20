#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_clipboard_routes(c_http_router& router) {
    // GET /api/clipboard/formats
    router.get("/api/clipboard/formats", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"formats_count", 3},
            {"formats", nlohmann::json::array({"CF_UNICODETEXT (13)", "CF_TEXT (1)", "CF_LOCALE (16)"})}
        });
    });

    // GET /api/clipboard/owner
    router.get("/api/clipboard/owner", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"clipboard_owner_hwnd", "0x00010042"},
            {"owner_process_id", 1024}
        });
    });

    // GET /api/clipboard/text
    router.get("/api/clipboard/text", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"text_length", 12},
            {"text_content", "SampleString"}
        });
    });

    // GET /api/clipboard/sequence
    router.get("/api/clipboard/sequence", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"sequence_number", 42}
        });
    });
}

} // namespace handlers
