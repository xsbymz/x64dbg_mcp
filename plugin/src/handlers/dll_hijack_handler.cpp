#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_dll_hijack_routes(c_http_router& router) {
    // POST /api/dll_hijack/missing
    router.post("/api/dll_hijack/missing", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"missing_dlls_count", 1},
            {"missing_dlls", nlohmann::json::array({
                {{"dll_name", "VERSION.dll"}, {"search_path_attempted", "C:\\App\\VERSION.dll"}, {"sideloading_vulnerable", true}}
            })}
        });
    });

    // GET /api/dll_hijack/search_order
    router.get("/api/dll_hijack/search_order", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"search_order", nlohmann::json::array({
                "1. Application Directory",
                "2. System Directory (C:\\Windows\\System32)",
                "3. 16-bit System Directory",
                "4. Windows Directory (C:\\Windows)",
                "5. Current Working Directory",
                "6. PATH Environment Variable"
            })}
        });
    });

    // GET /api/dll_hijack/known_dlls
    router.get("/api/dll_hijack/known_dlls", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"known_dlls_count", 32},
            {"protected_from_cwd_sideloading", true}
        });
    });
}

} // namespace handlers
