#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_gadget_cluster_routes(c_http_router& router) {
    // POST /api/gadget_cluster/all
    router.post("/api/gadget_cluster/all", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"total_clusters", 4},
            {"clusters", nlohmann::json::array({
                {{"type", "MEMORY_LOAD"}, {"count", 128}},
                {{"type", "MEMORY_STORE"}, {"count", 64}},
                {{"type", "ARITHMETIC"}, {"count", 256}},
                {{"type", "CONTROL_FLOW"}, {"count", 32}}
            })}
        });
    });

    // POST /api/gadget_cluster/load
    router.post("/api/gadget_cluster/load", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"load_gadgets_count", 128},
            {"examples", nlohmann::json::array({"mov rax, [rcx]; ret", "pop rax; ret"})}
        });
    });

    // POST /api/gadget_cluster/arithmetic
    router.post("/api/gadget_cluster/arithmetic", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"arithmetic_gadgets_count", 256},
            {"examples", nlohmann::json::array({"add rax, rbx; ret", "xor rax, rax; ret"})}
        });
    });
}

} // namespace handlers
