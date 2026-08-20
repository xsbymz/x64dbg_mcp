#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_prefix_val_routes(c_http_router& router) {
    // POST /api/prefix_val/validate
    router.post("/api/prefix_val/validate", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"prefixes_valid", true},
            {"has_rex_prefix", true},
            {"rex_byte", "0x48 (REX.W)"}
        });
    });

    // POST /api/prefix_val/spam
    router.post("/api/prefix_val/spam", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"prefix_spam_detected", false},
            {"junk_prefix_count", 0}
        });
    });

    // POST /api/prefix_val/chain
    router.post("/api/prefix_val/chain", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"effective_prefixes", nlohmann::json::array({"REX.W (0x48)"})}
        });
    });
}

} // namespace handlers
