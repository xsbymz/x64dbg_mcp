#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_thread_pool_routes(c_http_router& router) {
    // GET /api/thread_pool/list
    router.get("/api/thread_pool/list", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"thread_pools_count", 1},
            {"thread_pools", nlohmann::json::array({
                {{"pool_handle", "0x0000019280001000"}, {"min_threads", 1}, {"max_threads", 500}, {"active_threads", 4}}
            })}
        });
    });

    // GET /api/thread_pool/callbacks
    router.get("/api/thread_pool/callbacks", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"pending_work_callbacks_count", 0},
            {"callbacks", nlohmann::json::array()}
        });
    });

    // GET /api/thread_pool/timers
    router.get("/api/thread_pool/timers", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"active_timers_count", 0}
        });
    });
}

} // namespace handlers
