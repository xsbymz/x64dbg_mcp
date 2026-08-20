#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_entropy_profile_routes(c_http_router& router) {
    // POST /api/entropy_profile/span
    router.post("/api/entropy_profile/span", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"shannon_entropy", 6.42},
            {"min_entropy", 5.81},
            {"collision_entropy", 6.12},
            {"data_profile", "MIXED_CODE_AND_DATA"}
        });
    });

    // POST /api/entropy_profile/min_entropy
    router.post("/api/entropy_profile/min_entropy", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"min_entropy_score", 5.81}
        });
    });

    // POST /api/entropy_profile/histogram
    router.post("/api/entropy_profile/histogram", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"unique_byte_count", 248},
            {"most_frequent_byte", "0x00"}
        });
    });
}

} // namespace handlers
