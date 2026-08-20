#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_ideal_proc_routes(c_http_router& router) {
    // POST /api/ideal_proc/get
    router.post("/api/ideal_proc/get", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"group", 0},
            {"ideal_processor_number", 2},
            {"status", "IDEAL_PROCESSOR_QUERIED"}
        });
    });

    // POST /api/ideal_proc/set
    router.post("/api/ideal_proc/set", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"previous_ideal_processor", 2},
            {"status", "IDEAL_PROCESSOR_SET"}
        });
    });

    // GET /api/ideal_proc/all
    router.get("/api/ideal_proc/all", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"threads_count", 1},
            {"threads", nlohmann::json::array({
                {{"thread_id", 1024}, {"group", 0}, {"processor", 2}}
            })}
        });
    });
}

} // namespace handlers
