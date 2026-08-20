#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_sec_desc_routes(c_http_router& router) {
    // POST /api/sec_desc/handle
    router.post("/api/sec_desc/handle", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"owner_sid", "S-1-5-32-544"},
            {"group_sid", "S-1-5-18"},
            {"dacl_present", true},
            {"sacl_present", false},
            {"control_flags", "SE_DACL_PRESENT | SE_SELF_RELATIVE"}
        });
    });

    // POST /api/sec_desc/address
    router.post("/api/sec_desc/address", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"revision", 1},
            {"owner_sid", "S-1-5-18"},
            {"status", "VALID_SECURITY_DESCRIPTOR"}
        });
    });

    // POST /api/sec_desc/dacl
    router.post("/api/sec_desc/dacl", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"ace_count", 2},
            {"aces", nlohmann::json::array({
                {{"type", "ACCESS_ALLOWED_ACE_TYPE"}, {"mask", "GENERIC_ALL"}, {"sid", "S-1-5-18"}}
            })}
        });
    });
}

} // namespace handlers
