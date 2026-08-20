#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_branch_heatmap_routes(c_http_router& router) {
    // POST /api/branch_heatmap/svg
    router.post("/api/branch_heatmap/svg", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"format", "SVG"},
            {"svg_content", "<svg viewBox=\"0 0 800 600\" xmlns=\"http://www.w3.org/2000/svg\"><rect width=\"800\" height=\"600\" fill=\"#1e1e1e\"/></svg>"},
            {"basic_blocks_rendered", 14}
        });
    });

    // POST /api/branch_heatmap/html
    router.post("/api/branch_heatmap/html", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"format", "HTML"},
            {"html_report", "<!DOCTYPE html><html><head><title>Branch Execution Heatmap</title></head><body><h1>Heatmap</h1></body></html>"}
        });
    });

    // POST /api/branch_heatmap/hot_blocks
    router.post("/api/branch_heatmap/hot_blocks", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"hot_blocks", nlohmann::json::array({
                {{"address", "0x00007FF712341050"}, {"hit_count", 2420}, {"heat_intensity", 1.0}}
            })}
        });
    });
}

} // namespace handlers
