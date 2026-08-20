#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_globalptr_routes(c_http_router& router) {
    // GET /api/globalptr/parse
    router.get("/api/globalptr/parse", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"global_pointer_rva", "0x00000000"},
            {"global_pointer_size", 0},
            {"is_gp_used", false}
        });
    });

    // GET /api/globalptr/target
    router.get("/api/globalptr/target", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"target_address", "0x0000000000000000"}
        });
    });

    // GET /api/globalptr/validity
    router.get("/api/globalptr/validity", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"is_valid", true}
        });
    });
}

} // namespace handlers
