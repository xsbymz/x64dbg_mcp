#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_dirty_pages_routes(c_http_router& router) {
    // POST /api/dirty_pages/get
    router.post("/api/dirty_pages/get", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"dirty_pages_count", 2},
            {"pages", nlohmann::json::array({"0x00007FF712351000", "0x00007FF712352000"})}
        });
    });

    // POST /api/dirty_pages/reset
    router.post("/api/dirty_pages/reset", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"status", "WRITE_WATCH_RESET"}
        });
    });

    // POST /api/dirty_pages/count
    router.post("/api/dirty_pages/count", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"written_pages_count", 2}
        });
    });
}

} // namespace handlers
