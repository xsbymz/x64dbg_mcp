#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_golang_scheduler_routes(c_http_router& router) {
    // POST /api/golang/enum_goroutines
    router.post("/api/golang/enum_goroutines", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"total_goroutines", 4},
            {"goroutines", nlohmann::json::array({
                {{"goid", 1}, {"status", "_Grunning"}, {"entry_func", "main.main"}},
                {{"goid", 2}, {"status", "_Gwaiting"}, {"entry_func", "runtime.forcegchelper"}}
            })}
        });
    });

    // POST /api/golang/inspect_channel
    router.post("/api/golang/inspect_channel", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"channel_element_size", 8},
            {"channel_buffer_capacity", 16},
            {"channel_current_count", 0},
            {"closed", false}
        });
    });
}

} // namespace handlers
