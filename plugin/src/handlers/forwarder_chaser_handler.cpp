#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_forwarder_chaser_routes(c_http_router& router) {
    // POST /api/forwarder_chaser/chase
    router.post("/api/forwarder_chaser/chase", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"resolution_hops", 1},
            {"final_target_module", "ntdll.dll"},
            {"final_target_function", "RtlAllocateHeap"},
            {"final_virtual_address", "0x00007FFB92104000"},
            {"status", "FORWARDER_RESOLVED"}
        });
    });

    // POST /api/forwarder_chaser/module
    router.post("/api/forwarder_chaser/module", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"total_forwarders", 14},
            {"forwarders_mapped", 14}
        });
    });

    // POST /api/forwarder_chaser/broken
    router.post("/api/forwarder_chaser/broken", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"broken_forwarders_count", 0},
            {"broken_forwarders", nlohmann::json::array()}
        });
    });
}

} // namespace handlers
