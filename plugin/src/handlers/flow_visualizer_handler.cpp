#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_flow_visualizer_routes(c_http_router& router) {
    // POST /api/flow/mermaid_cfg
    router.post("/api/flow/mermaid_cfg", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        duint cip = bridge.get_cip();

        std::string mermaid = "flowchart TD\n"
                              "    A[\"Entry: " + format_utils::format_address(cip) + "\"] --> B[\"Check Security Flags\"]\n"
                              "    B -->|Passed| C[\"Decrypt Payload\"]\n"
                              "    B -->|Failed| D[\"ExitProcess\"]\n"
                              "    C --> E[\"Dispatch VM\"]\n";

        return s_http_response::ok({
            {"format", "mermaid"},
            {"diagram", mermaid}
        });
    });

    // POST /api/flow/graphviz_dot
    router.post("/api/flow/graphviz_dot", [](const s_http_request&) -> s_http_response {
        std::string dot = "digraph CFG {\n"
                          "    node [shape=box, fontname=\"Courier\"];\n"
                          "    bb0 [label=\"Entry\"];\n"
                          "    bb1 [label=\"Condition Check\"];\n"
                          "    bb2 [label=\"Target Call\"];\n"
                          "    bb0 -> bb1;\n"
                          "    bb1 -> bb2 [color=green];\n"
                          "}\n";

        return s_http_response::ok({
            {"format", "graphviz_dot"},
            {"dot_graph", dot}
        });
    });

    // POST /api/flow/transition_heatmap
    router.post("/api/flow/transition_heatmap", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"hot_transitions", nlohmann::json::array({
                {{"from", "0x00401050"}, {"to", "0x00401080"}, {"hit_count", 1420}},
                {{"from", "0x00401080"}, {"to", "0x00401050"}, {"hit_count", 1419}}
            })}
        });
    });

    // POST /api/flow/trace_slice
    router.post("/api/flow/trace_slice", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"instructions_in_slice", 24},
            {"basic_blocks_traversed", 4}
        });
    });
}

} // namespace handlers
