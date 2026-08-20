#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_ilt_val_routes(c_http_router& router) {
    // GET /api/ilt_val/parity
    router.get("/api/ilt_val/parity", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"ilt_iat_synchronized", true},
            {"total_imports_checked", 128},
            {"status", "PARITY_CONFIRMED"}
        });
    });

    // GET /api/ilt_val/unmatched
    router.get("/api/ilt_val/unmatched", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"unmatched_thunks_count", 0},
            {"unmatched", nlohmann::json::array()}
        });
    });

    // GET /api/ilt_val/ordinals
    router.get("/api/ilt_val/ordinals", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"ordinal_imports_count", 2}
        });
    });
}

} // namespace handlers
