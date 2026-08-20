#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <algorithm>
#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

// ---------------------------------------------------------------------------
// CFG / Call Tree builder
// ---------------------------------------------------------------------------

struct call_node {
    duint       address;
    std::string label;
    std::string module;
    int         depth;
    bool        is_recursive = false;
    bool        is_external  = false; // resolved to a different module
    std::vector<duint> callees;
};

// Build an N-level call tree by disassembling each function and collecting
// all CALLs with known targets. BFS-bounded by max_depth and max_nodes.
static std::unordered_map<duint, call_node>
build_call_tree(c_bridge_executor& bridge, duint root_addr,
                int max_depth, int max_nodes, const std::string& root_module) {

    std::unordered_map<duint, call_node> tree;
    std::queue<std::pair<duint, int>> worklist;
    worklist.push({root_addr, 0});

    while (!worklist.empty() && static_cast<int>(tree.size()) < max_nodes) {
        auto [addr, depth] = worklist.front();
        worklist.pop();

        if (tree.count(addr)) continue;

        call_node node;
        node.address = addr;
        node.depth   = depth;
        node.label   = bridge.get_label_at(addr);
        node.module  = bridge.get_module_at(addr);
        node.is_external = (!root_module.empty() && node.module != root_module);

        // Get function bounds
        duint fstart = 0, fend = 0;
        bool has_bounds = DbgFunctionGet(addr, &fstart, &fend);

        if (has_bounds && !node.is_external) {
            // Walk the function and collect direct call targets
            auto cur = fstart;
            while (cur <= fend) {
                BASIC_INSTRUCTION_INFO bi{};
                DbgDisasmFastAt(cur, &bi);
                if (bi.size == 0) break;

                if (bi.call && bi.branch && bi.addr != 0 && bi.addr != addr) {
                    node.callees.push_back(bi.addr);
                    if (bi.addr == addr) {
                        node.is_recursive = true;
                    }
                }

                cur += bi.size;
            }

            // Deduplicate callees
            std::sort(node.callees.begin(), node.callees.end());
            node.callees.erase(std::unique(node.callees.begin(), node.callees.end()),
                               node.callees.end());
        }

        tree[addr] = node;

        // Enqueue children if within depth limit
        if (depth < max_depth) {
            for (auto callee : node.callees) {
                if (!tree.count(callee)) {
                    worklist.push({callee, depth + 1});
                }
            }
        }
    }

    return tree;
}

// Serialize tree node to JSON
static nlohmann::json node_to_json(const call_node& n) {
    auto callees = nlohmann::json::array();
    for (auto c : n.callees) callees.push_back(format_utils::format_address(c));

    return nlohmann::json{
        {"address",      format_utils::format_address(n.address)},
        {"label",        n.label},
        {"module",       n.module},
        {"depth",        n.depth},
        {"is_recursive", n.is_recursive},
        {"is_external",  n.is_external},
        {"callees",      callees},
        {"callee_count", n.callees.size()}
    };
}

// Build nested JSON tree (recursive)
static nlohmann::json build_nested(const std::unordered_map<duint, call_node>& tree,
                                    duint addr, int max_depth,
                                    std::unordered_set<duint>& visited) {
    if (visited.count(addr) || !tree.count(addr)) {
        return nlohmann::json{
            {"address", format_utils::format_address(addr)},
            {"note",    "cycle or not expanded"}
        };
    }
    visited.insert(addr);

    const auto& n = tree.at(addr);
    auto obj = node_to_json(n);

    if (n.depth < max_depth && !n.is_external) {
        auto children = nlohmann::json::array();
        for (auto c : n.callees) {
            children.push_back(build_nested(tree, c, max_depth, visited));
        }
        obj["children"] = children;
    }

    return obj;
}

// Detect back edges (loops) via DFS
static std::vector<std::pair<duint,duint>> detect_loops(
    const std::unordered_map<duint, call_node>& tree, duint root) {

    std::vector<std::pair<duint,duint>> back_edges;
    std::unordered_set<duint> on_stack, visited;

    std::function<void(duint)> dfs = [&](duint addr) {
        if (!tree.count(addr)) return;
        visited.insert(addr);
        on_stack.insert(addr);

        for (auto callee : tree.at(addr).callees) {
            if (on_stack.count(callee)) {
                back_edges.push_back({addr, callee}); // back edge = loop
            } else if (!visited.count(callee)) {
                dfs(callee);
            }
        }
        on_stack.erase(addr);
    };

    dfs(root);
    return back_edges;
}

// Export flat call graph as DOT language
static std::string export_dot(const std::unordered_map<duint, call_node>& tree) {
    std::string dot = "digraph CallGraph {\n";
    dot += "  rankdir=LR;\n";
    dot += "  node [shape=box, fontname=\"Courier\"];\n";

    for (const auto& [addr, node] : tree) {
        auto label = node.label.empty() ? format_utils::format_address(addr) : node.label;
        // Escape double quotes
        std::string safe_label;
        for (char c : label) safe_label += (c == '"') ? '\'' : c;

        std::string color = node.is_recursive ? " fillcolor=orange style=filled" :
                            node.is_external  ? " fillcolor=lightblue style=filled" : "";
        char node_def[512];
        std::snprintf(node_def, sizeof(node_def),
                      "  n%llX [label=\"%s\\n%s\"%s];\n",
                      static_cast<unsigned long long>(addr),
                      safe_label.c_str(),
                      format_utils::format_address(addr).c_str(),
                      color.c_str());
        dot += node_def;

        for (auto callee : node.callees) {
            char edge[128];
            std::snprintf(edge, sizeof(edge),
                          "  n%llX -> n%llX;\n",
                          static_cast<unsigned long long>(addr),
                          static_cast<unsigned long long>(callee));
            dot += edge;
        }
    }
    dot += "}\n";
    return dot;
}

// Export as Mermaid flowchart
static std::string export_mermaid(const std::unordered_map<duint, call_node>& tree) {
    std::string out = "flowchart LR\n";
    for (const auto& [addr, node] : tree) {
        auto label = node.label.empty() ? format_utils::format_address(addr) : node.label;
        std::string safe;
        for (char c : label) {
            if (c == '"' || c == '[' || c == ']' || c == '(' || c == ')') safe += '_';
            else safe += c;
        }
        for (auto callee : node.callees) {
            out += "  " + safe + " --> ";
            if (tree.count(callee)) {
                auto cl = tree.at(callee).label;
                if (cl.empty()) cl = format_utils::format_address(callee);
                for (char c : cl) {
                    if (c == '"' || c == '[' || c == ']' || c == '(' || c == ')') out += '_';
                    else out += c;
                }
            } else {
                out += format_utils::format_address(callee);
            }
            out += "\n";
        }
    }
    return out;
}

// ---------------------------------------------------------------------------

void register_calltree_routes(c_http_router& router) {

    // GET /api/calltree/from?address=0x...&depth=3&max_nodes=500&include_external=false
    router.get("/api/calltree/from", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto addr_str       = req.get_query("address", "cip");
        int  max_depth      = std::atoi(req.get_query("depth", "3").c_str());
        int  max_nodes      = std::atoi(req.get_query("max_nodes", "500").c_str());
        bool include_ext    = (req.get_query("include_external", "false") == "true");
        bool nested         = (req.get_query("nested", "false") == "true");

        if (max_depth < 1) max_depth = 1;
        if (max_depth > 10) max_depth = 10;
        if (max_nodes < 1) max_nodes = 1;
        if (max_nodes > 5000) max_nodes = 5000;

        auto root_addr = bridge.eval_expression(addr_str);
        if (root_addr == 0) {
            return s_http_response::bad_request("Could not evaluate address: " + addr_str);
        }

        auto root_module = bridge.get_module_at(root_addr);

        auto tree = build_call_tree(bridge, root_addr, max_depth, max_nodes,
                                    include_ext ? "" : root_module);

        if (nested) {
            std::unordered_set<duint> visited;
            return s_http_response::ok({
                {"root",       format_utils::format_address(root_addr)},
                {"node_count", tree.size()},
                {"depth",      max_depth},
                {"tree",       build_nested(tree, root_addr, max_depth, visited)}
            });
        }

        // Flat mode
        auto flat = nlohmann::json::array();
        for (const auto& [addr, node] : tree) {
            flat.push_back(node_to_json(node));
        }

        return s_http_response::ok({
            {"root",       format_utils::format_address(root_addr)},
            {"node_count", flat.size()},
            {"depth",      max_depth},
            {"nodes",      flat}
        });
    });

    // GET /api/calltree/loop_detect?address=0x...&depth=4
    router.get("/api/calltree/loop_detect", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto addr_str  = req.get_query("address", "cip");
        int  max_depth = std::atoi(req.get_query("depth", "4").c_str());
        int  max_nodes = std::atoi(req.get_query("max_nodes", "1000").c_str());
        if (max_depth > 8) max_depth = 8;
        if (max_nodes > 5000) max_nodes = 5000;

        auto root = bridge.eval_expression(addr_str);
        auto root_mod = bridge.get_module_at(root);

        auto tree     = build_call_tree(bridge, root, max_depth, max_nodes, root_mod);
        auto back_edges = detect_loops(tree, root);

        auto loops = nlohmann::json::array();
        for (const auto& [from, to] : back_edges) {
            auto from_label = tree.count(from) ? tree.at(from).label : "";
            auto to_label   = tree.count(to)   ? tree.at(to).label   : "";
            loops.push_back({
                {"from_address", format_utils::format_address(from)},
                {"from_label",   from_label},
                {"to_address",   format_utils::format_address(to)},
                {"to_label",     to_label},
                {"type",         from == to ? "self_recursion" : "mutual_recursion"}
            });
        }

        return s_http_response::ok({
            {"root",           format_utils::format_address(root)},
            {"nodes_explored", tree.size()},
            {"back_edges",     loops},
            {"loop_count",     loops.size()}
        });
    });

    // POST /api/calltree/export
    // Body: { "address": "0x...", "depth": 3, "format": "dot|mermaid|json" }
    router.post("/api/calltree/export", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto body      = nlohmann::json::parse(req.body, nullptr, false);
        auto addr_str  = body.is_discarded() ? "cip" : body.value("address", "cip");
        int  max_depth = body.is_discarded() ? 3    : body.value("depth", 3);
        int  max_nodes = body.is_discarded() ? 500  : body.value("max_nodes", 500);
        auto fmt       = body.is_discarded() ? "dot": body.value("format", "dot");

        if (max_depth > 8) max_depth = 8;
        if (max_nodes > 5000) max_nodes = 5000;

        auto root = bridge.eval_expression(addr_str);
        auto root_mod = bridge.get_module_at(root);
        auto tree = build_call_tree(bridge, root, max_depth, max_nodes, root_mod);

        std::string output;
        if (fmt == "dot") {
            output = export_dot(tree);
        } else if (fmt == "mermaid") {
            output = export_mermaid(tree);
        } else {
            // JSON flat
            auto flat = nlohmann::json::array();
            for (const auto& [addr, node] : tree) flat.push_back(node_to_json(node));
            output = flat.dump(2);
        }

        return s_http_response::ok({
            {"format",     fmt},
            {"root",       format_utils::format_address(root)},
            {"node_count", tree.size()},
            {"output",     output},
            {"note",       fmt == "dot" ?
                "Paste into https://dreampuf.github.io/GraphvizOnline to visualize" :
                fmt == "mermaid" ?
                "Paste into https://mermaid.live to visualize" : ""}
        });
    });

    // GET /api/calltree/dominators?address=0x...
    // Compute a simplified dominator tree using a BFS-based approximation.
    router.get("/api/calltree/dominators", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto addr_str  = req.get_query("address", "cip");
        int  max_depth = std::atoi(req.get_query("depth", "4").c_str());
        if (max_depth > 6) max_depth = 6;

        auto root     = bridge.eval_expression(addr_str);
        auto root_mod = bridge.get_module_at(root);
        auto tree     = build_call_tree(bridge, root, max_depth, 1000, root_mod);

        // Simplified immediate dominators: for BFS, the node that first
        // enqueued a node is its "idom" (not full Lengauer-Tarjan, but useful).
        std::unordered_map<duint, duint> idom;
        std::queue<duint> bfs;
        bfs.push(root);
        idom[root] = root;

        while (!bfs.empty()) {
            auto u = bfs.front(); bfs.pop();
            if (!tree.count(u)) continue;
            for (auto v : tree.at(u).callees) {
                if (!idom.count(v)) {
                    idom[v] = u;
                    bfs.push(v);
                }
            }
        }

        auto doms = nlohmann::json::array();
        for (const auto& [node_addr, dom_addr] : idom) {
            if (node_addr == root) continue;
            doms.push_back({
                {"address",          format_utils::format_address(node_addr)},
                {"label",            tree.count(node_addr) ? tree.at(node_addr).label : ""},
                {"immediate_dom",    format_utils::format_address(dom_addr)},
                {"idom_label",       tree.count(dom_addr)  ? tree.at(dom_addr).label  : ""}
            });
        }

        return s_http_response::ok({
            {"root",       format_utils::format_address(root)},
            {"dominators", doms},
            {"count",      doms.size()},
            {"note",       "BFS approximation of immediate dominators. For precise results use Lengauer-Tarjan."}
        });
    });
}

} // namespace handlers
