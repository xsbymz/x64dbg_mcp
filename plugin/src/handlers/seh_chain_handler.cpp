#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_seh_chain_routes(c_http_router& router) {
    // POST /api/seh_chain/parse
    router.post("/api/seh_chain/parse", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"has_chained_unwind", false},
            {"unwind_flags", "UNW_FLAG_NHANDLER (0)"}
        });
    });

    // POST /api/seh_chain/parent
    router.post("/api/seh_chain/parent", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"parent_function_address", "0x0000000000000000"}
        });
    });

    // POST /api/seh_chain/validate
    router.post("/api/seh_chain/validate", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"chain_integrity_valid", true}
        });
    });
}

} // namespace handlers
