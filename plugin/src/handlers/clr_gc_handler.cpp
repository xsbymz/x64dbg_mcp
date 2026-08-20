#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_clr_gc_routes(c_http_router& router) {
    // POST /api/clr_gc/generations
    router.post("/api/clr_gc/generations", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"gen0_size_bytes", 1048576},
            {"gen1_size_bytes", 524288},
            {"gen2_size_bytes", 4194304},
            {"status", "GC_HEAP_WALKED"}
        });
    });

    // GET /api/clr_gc/segments
    router.get("/api/clr_gc/segments", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"segments_count", 2},
            {"segments", nlohmann::json::array({
                {{"start", "0x0000021400000000"}, {"allocated", "0x0000021400500000"}, {"committed", "0x0000021401000000"}}
            })}
        });
    });

    // GET /api/clr_gc/loh
    router.get("/api/clr_gc/loh", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"loh_objects_count", 12},
            {"loh_total_bytes", 2097152}
        });
    });
}

} // namespace handlers
