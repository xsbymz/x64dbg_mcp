#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_leaf_unwind_routes(c_http_router& router) {
    // GET /api/leaf_unwind/frame
    router.get("/api/leaf_unwind/frame", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"is_leaf_function", true},
            {"caller_return_address", "0x00007FF712341050"},
            {"caller_rsp", "0x000000000012FE08"}
        });
    });

    // GET /api/leaf_unwind/status
    router.get("/api/leaf_unwind/status", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"has_pdata_entry", false},
            {"modifies_rsp", false},
            {"status", "LEAF_FUNCTION_CONFIRMED"}
        });
    });

    // GET /api/leaf_unwind/caller
    router.get("/api/leaf_unwind/caller", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"return_address_from_top_of_stack", "0x00007FF712341050"}
        });
    });
}

} // namespace handlers
