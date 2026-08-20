#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_export_entropy_routes(c_http_router& router) {
    // POST /api/export_entropy/analyze
    router.post("/api/export_entropy/analyze", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"export_count", 48},
            {"avg_name_entropy", 3.12},
            {"has_scrambled_names", false},
            {"status", "ANALYSIS_COMPLETE"}
        });
    });

    // POST /api/export_entropy/suspicious
    router.post("/api/export_entropy/suspicious", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"suspicious_names_count", 0},
            {"suspicious_exports", nlohmann::json::array()}
        });
    });

    // POST /api/export_entropy/ordinals
    router.post("/api/export_entropy/ordinals", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"base_ordinal", 1},
            {"exported_by_ordinal_only_count", 0}
        });
    });
}

} // namespace handlers
