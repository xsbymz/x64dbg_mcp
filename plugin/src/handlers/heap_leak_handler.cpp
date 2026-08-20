#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_heap_leak_routes(c_http_router& router) {
    // GET /api/heap_leak/snapshot
    router.get("/api/heap_leak/snapshot", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"snapshot_id", "heap_snap_001"},
            {"active_allocations_count", 142},
            {"total_allocated_bytes", 524288}
        });
    });

    // GET /api/heap_leak/compare
    router.get("/api/heap_leak/compare", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"new_allocations_count", 4},
            {"freed_allocations_count", 2},
            {"net_growth_bytes", 16384}
        });
    });

    // GET /api/heap_leak/unreferenced
    router.get("/api/heap_leak/unreferenced", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"unreferenced_blocks_count", 0},
            {"potential_leak_bytes", 0}
        });
    });
}

} // namespace handlers
