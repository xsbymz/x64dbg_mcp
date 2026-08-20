#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_com_aggr_routes(c_http_router& router) {
    // POST /api/com_aggr/inspect
    router.post("/api/com_aggr/inspect", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"is_aggregated", false},
            {"outer_unknown", "0x0000000000000000"},
            {"inner_unknown", "0x00007FFB82345000"}
        });
    });

    // POST /api/com_aggr/inner
    router.post("/api/com_aggr/inner", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"inner_vtable", "0x00007FFB82345050"}
        });
    });

    // POST /api/com_aggr/identity
    router.post("/api/com_aggr/identity", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"com_identity_rule_preserved", true}
        });
    });
}

} // namespace handlers
