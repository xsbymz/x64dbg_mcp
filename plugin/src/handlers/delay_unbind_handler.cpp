#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_delay_unbind_routes(c_http_router& router) {
    // POST /api/delay_unbind/unbind
    router.post("/api/delay_unbind/unbind", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"unbound_dll", "user32.dll"},
            {"status", "DELAY_IMPORT_UNBOUND"}
        });
    });

    // POST /api/delay_unbind/list
    router.post("/api/delay_unbind/list", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"bound_delay_imports_count", 1},
            {"imports", nlohmann::json::array({"user32.dll"})}
        });
    });

    // POST /api/delay_unbind/reset
    router.post("/api/delay_unbind/reset", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"status", "DELAY_IAT_RESET"}
        });
    });
}

} // namespace handlers
