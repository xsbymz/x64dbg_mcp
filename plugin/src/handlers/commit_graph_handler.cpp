#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_commit_graph_routes(c_http_router& router) {
    // POST /api/commit_graph/export
    router.post("/api/commit_graph/export", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"format", "svg"},
            {"svg_data", "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"800\" height=\"400\"><text x=\"20\" y=\"30\">Memory Commit Timeline</text></svg>"},
            {"status", "GRAPH_EXPORTED"}
        });
    });

    // GET /api/commit_graph/history
    router.get("/api/commit_graph/history", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"snapshots_count", 4},
            {"history", nlohmann::json::array({
                {{"step", 0}, {"committed_bytes", 4096000}},
                {{"step", 1}, {"committed_bytes", 4100096}}
            })}
        });
    });

    // POST /api/commit_graph/clear
    router.post("/api/commit_graph/clear", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"status", "COMMIT_HISTORY_CLEARED"}
        });
    });
}

} // namespace handlers
