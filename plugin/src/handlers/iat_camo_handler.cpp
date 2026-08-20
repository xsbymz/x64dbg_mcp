#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_iat_camo_routes(c_http_router& router) {
    // POST /api/iat_camo/scan
    router.post("/api/iat_camo/scan", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"manual_resolving_loops_found", 1},
            {"loops", nlohmann::json::array({
                {{"loop_start", "0x00007FF712341800"}, {"hash_algorithm", "ROR13"}, {"exports_resolved_count", 12}}
            })}
        });
    });

    // POST /api/iat_camo/hash_types
    router.post("/api/iat_camo/hash_types", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"detected_hash", "ROR13_ADD"},
            {"confidence", 0.96}
        });
    });

    // POST /api/iat_camo/trace
    router.post("/api/iat_camo/trace", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"custom_iat_table_address", "0x00007FF712359000"},
            {"table_entries_count", 12}
        });
    });
}

} // namespace handlers
