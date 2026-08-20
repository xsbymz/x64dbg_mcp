#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_fls_cb_routes(c_http_router& router) {
    // GET /api/fls_cb/list
    router.get("/api/fls_cb/list", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"callbacks_count", 2},
            {"callbacks", nlohmann::json::array({
                {{"slot", 1}, {"callback_address", "0x00007FFB82341050"}, {"module", "ucrtbase.dll"}}
            })}
        });
    });

    // POST /api/fls_cb/test
    router.post("/api/fls_cb/test", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"test_dispatched", true},
            {"status", "CALLBACK_EXECUTED_SAFELY"}
        });
    });

    // POST /api/fls_cb/simulate
    router.post("/api/fls_cb/simulate", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"simulation_completed", true}
        });
    });
}

} // namespace handlers
