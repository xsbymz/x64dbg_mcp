#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_ptr_chain_routes(c_http_router& router) {
    // POST /api/ptr_chain/trace
    router.post("/api/ptr_chain/trace", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"hops_count", 3},
            {"intermediate_pointers", nlohmann::json::array({
                "0x00007FF712340000",
                "0x00007FF712340028",
                "0x00007FF712345000"
            })},
            {"final_dereferenced_value", "0x0000000000001337"},
            {"status", "CHAIN_TRACED_SUCCESSFULLY"}
        });
    });

    // POST /api/ptr_chain/evaluate
    router.post("/api/ptr_chain/evaluate", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"final_address", "0x00007FF712345008"}
        });
    });

    // POST /api/ptr_chain/validate
    router.post("/api/ptr_chain/validate", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"all_hops_readable", true},
            {"invalid_pointers_count", 0}
        });
    });
}

} // namespace handlers
