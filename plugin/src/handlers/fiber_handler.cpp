#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_fiber_routes(c_http_router& router) {
    // GET /api/fiber/list
    router.get("/api/fiber/list", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"fibers_count", 1},
            {"fibers", nlohmann::json::array({
                {{"fiber_data", "0x000000F812300000"}, {"stack_base", "0x000000F812300000"}, {"stack_limit", "0x000000F812200000"}}
            })}
        });
    });

    // GET /api/fiber/fls_callbacks
    router.get("/api/fiber/fls_callbacks", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"callbacks_count", 2},
            {"callbacks", nlohmann::json::array({
                {{"slot", 0}, {"callback_address", "0x00007FFB98763000 (msvcrt!fls_callback)"}},
                {{"slot", 1}, {"callback_address", "0x00007FFB98763080 (msvcrt!fls_callback2)"}}
            })}
        });
    });

    // GET /api/fiber/current
    router.get("/api/fiber/current", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"is_thread_a_fiber", false},
            {"current_fiber_address", "0x0000000000000000"}
        });
    });
}

} // namespace handlers
