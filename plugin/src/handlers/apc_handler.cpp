#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_apc_routes(c_http_router& router) {
    // POST /api/apc/thread_queue
    router.post("/api/apc/thread_queue", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"user_apcs_queued_count", 0},
            {"special_kernel_apcs_count", 0}
        });
    });

    // GET /api/apc/all_queues
    router.get("/api/apc/all_queues", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"total_queued_apcs", 0},
            {"threads_with_apcs", nlohmann::json::array()}
        });
    });

    // GET /api/apc/alertable_threads
    router.get("/api/apc/alertable_threads", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"alertable_threads_count", 1},
            {"threads", nlohmann::json::array({
                {{"tid", 1024}, {"wait_reason", "UserRequest (SleepEx Alertable)"}}
            })}
        });
    });
}

} // namespace handlers
