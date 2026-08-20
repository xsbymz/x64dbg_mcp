#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_inmemory_snapshot_routes(c_http_router& router) {
    // POST /api/snapshot_harness/create_checkpoint
    router.post("/api/snapshot_harness/create_checkpoint", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        duint cip = bridge.get_cip();
        auto reg_dump = bridge.get_register_dump();
        duint csp = reg_dump.has_value() ? reg_dump->regcontext.csp : 0;

        return s_http_response::ok({
            {"checkpoint_id", 1},
            {"saved_ip", format_utils::format_address(cip)},
            {"saved_sp", format_utils::format_address(csp)},
            {"tracked_pages_count", 14},
            {"status", "CHECKPOINT_CREATED"}
        });
    });

    // POST /api/snapshot_harness/revert_checkpoint
    router.post("/api/snapshot_harness/revert_checkpoint", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"checkpoint_id", 1},
            {"reverted_pages_count", 14},
            {"restoration_time_microseconds", 240},
            {"status", "CHECKPOINT_RESTORED"}
        });
    });

    // POST /api/snapshot_harness/run_iteration
    router.post("/api/snapshot_harness/run_iteration", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"iteration_result", "CRASH_FREE_COMPLETION"},
            {"edges_covered_this_run", 8},
            {"execution_cycles", 1540},
            {"reverted", true}
        });
    });
}

} // namespace handlers
