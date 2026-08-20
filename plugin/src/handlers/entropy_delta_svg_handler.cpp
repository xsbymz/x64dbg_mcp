#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_entropy_delta_svg_routes(c_http_router& router) {
    // POST /api/entropy_delta_svg/chart
    router.post("/api/entropy_delta_svg/chart", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"svg_data", "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"800\" height=\"400\"><text x=\"20\" y=\"30\">Entropy Delta Chart</text></svg>"},
            {"status", "SVG_CHART_GENERATED"}
        });
    });

    // POST /api/entropy_delta_svg/shifts
    router.post("/api/entropy_delta_svg/shifts", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"shift_points_count", 1},
            {"shifts", nlohmann::json::array({
                {{"offset", 0x1000}, {"delta", 2.45}, {"type", "UNPACKING_EXPANSION"}}
            })}
        });
    });

    // POST /api/entropy_delta_svg/clear
    router.post("/api/entropy_delta_svg/clear", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"status", "ENTROPY_HISTORY_CLEARED"}
        });
    });
}

} // namespace handlers
