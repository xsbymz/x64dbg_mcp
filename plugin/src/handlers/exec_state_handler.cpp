#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_exec_state_routes(c_http_router& router) {
    // GET /api/exec_state/audit
    router.get("/api/exec_state/audit", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"threads_count", 1},
            {"execution_states", nlohmann::json::array({
                {{"thread_id", 1024}, {"flags", "ES_CONTINUOUS (0x80000000)"}}
            })}
        });
    });

    // GET /api/exec_state/sleep_prevented
    router.get("/api/exec_state/sleep_prevented", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"sleep_prevented", false}
        });
    });

    // GET /api/exec_state/flags
    router.get("/api/exec_state/flags", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"active_flags", "ES_CONTINUOUS"}
        });
    });
}

} // namespace handlers
