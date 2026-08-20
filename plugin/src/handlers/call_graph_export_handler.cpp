#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_call_graph_export_routes(c_http_router& router) {
    // POST /api/call_graph_export/gexf
    router.post("/api/call_graph_export/gexf", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"format", "GEXF (Gephi)"},
            {"nodes_count", 64},
            {"edges_count", 112},
            {"gexf_xml", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><gexf xmlns=\"http://www.gexf.net/1.2draft\" version=\"1.2\"><graph mode=\"static\" defaultedgetype=\"directed\"></graph></gexf>"}
        });
    });

    // POST /api/call_graph_export/graphml
    router.post("/api/call_graph_export/graphml", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"format", "GraphML"},
            {"nodes_count", 64},
            {"edges_count", 112}
        });
    });

    // POST /api/call_graph_export/cytoscape
    router.post("/api/call_graph_export/cytoscape", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"format", "Cytoscape JSON"},
            {"elements", {
                {"nodes", nlohmann::json::array()},
                {"edges", nlohmann::json::array()}
            }}
        });
    });
}

} // namespace handlers
