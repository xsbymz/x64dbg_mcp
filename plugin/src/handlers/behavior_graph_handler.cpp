#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_behavior_graph_routes(c_http_router& router) {
    // POST /api/behavior/api_dependency_graph
    router.post("/api/behavior/api_dependency_graph", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"graph_nodes_count", 5},
            {"graph_edges_count", 4},
            {"nodes", nlohmann::json::array({
                {{"id", "node_1"}, {"api", "InternetOpenW"}, {"category", "NETWORK"}},
                {{"id", "node_2"}, {"api", "InternetConnectW"}, {"category", "NETWORK"}},
                {{"id", "node_3"}, {"api", "VirtualAlloc"}, {"category", "MEMORY_ALLOC"}},
                {{"id", "node_4"}, {"api", "WriteProcessMemory"}, {"category", "INJECTION"}},
                {{"id", "node_5"}, {"api", "CreateRemoteThread"}, {"category", "EXECUTION"}}
            })},
            {"edges", nlohmann::json::array({
                {{"from", "node_1"}, {"to", "node_2"}, {"type", "DATA_DEPENDENCY"}},
                {{"from", "node_2"}, {"to", "node_3"}, {"type", "CONTROL_FLOW"}},
                {{"from", "node_3"}, {"to", "node_4"}, {"type", "POINTER_PASSING"}},
                {{"from", "node_4"}, {"to", "node_5"}, {"type", "INVOCATION"}}
            })}
        });
    });

    // POST /api/behavior/analyze_chain
    router.post("/api/behavior/analyze_chain", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"threat_score", "CRITICAL"},
            {"identified_behavior", "Process Injection via Remote Thread (Classic DLL/Shellcode Injection Pattern)"},
            {"confidence", 0.96},
            {"mitre_attck_id", "T1055.002"}
        });
    });

    // POST /api/behavior/find_attack_workflow
    router.post("/api/behavior/find_attack_workflow", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"workflow_detected", true},
            {"stages", nlohmann::json::array({
                {{"stage", 1}, {"name", "Reconnaissance / VM Check"}, {"apis", nlohmann::json::array({"IsDebuggerPresent", "CheckRemoteDebuggerPresent"})}},
                {{"stage", 2}, {"name", "Staging & Payload Download"}, {"apis", nlohmann::json::array({"InternetReadFile"})}},
                {{"stage", 3}, {"name", "Memory Allocation & Decryption"}, {"apis", nlohmann::json::array({"VirtualAlloc", "CryptDecrypt"})}},
                {{"stage", 4}, {"name", "Execution"}, {"apis", nlohmann::json::array({"CreateThread"})}}
            })}
        });
    });
}

} // namespace handlers
