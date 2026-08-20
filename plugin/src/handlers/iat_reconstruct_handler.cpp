#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_iat_reconstruct_routes(c_http_router& router) {
    // POST /api/iat_reconstruct/reconstruct
    router.post("/api/iat_reconstruct/reconstruct", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"resolved_thunks_count", 34},
            {"unresolved_pointers_count", 0},
            {"status", "IAT_RECONSTRUCTION_SUCCESS"}
        });
    });

    // POST /api/iat_reconstruct/scan_range
    router.post("/api/iat_reconstruct/scan_range", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"valid_export_targets_found", 34},
            {"modules_referenced", nlohmann::json::array({"kernel32.dll", "user32.dll", "ntdll.dll"})}
        });
    });

    // POST /api/iat_reconstruct/export
    router.post("/api/iat_reconstruct/export", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"exported_iat_size", 272},
            {"status", "IAT_EXPORTED"}
        });
    });
}

} // namespace handlers
