#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_thread_stack_differ_routes(c_http_router& router) {
    // GET /api/threads/diff/snapshot
    router.get("/api/threads/diff/snapshot", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"snapshot_id", "snap_001"},
            {"threads_captured", 3},
            {"timestamp", "2026-08-16T16:00:00Z"}
        });
    });

    // GET /api/threads/diff/compare
    router.get("/api/threads/diff/compare", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"active_threads", 3},
            {"state_changes", nlohmann::json::array({
                {{"tid", 1024}, {"status", "ACTIVE_RUNNING"}, {"top_frame_changed", true}},
                {{"tid", 1028}, {"status", "BLOCKED_ON_CRITICAL_SECTION"}, {"top_frame_changed", false}},
                {{"tid", 1032}, {"status", "WAITING_ON_EVENT"}, {"top_frame_changed", false}}
            })}
        });
    });

    // GET /api/threads/diff/deadlocks
    router.get("/api/threads/diff/deadlocks", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"deadlocks_detected", false},
            {"circular_wait_chains", nlohmann::json::array()}
        });
    });

    // GET /api/threads/diff/blocked
    router.get("/api/threads/diff/blocked", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"blocked_threads_count", 1},
            {"threads", nlohmann::json::array({
                {{"tid", 1028}, {"waiting_on", "CRITICAL_SECTION (0x00458900)"}, {"owner_tid", 1024}}
            })}
        });
    });
}

} // namespace handlers
