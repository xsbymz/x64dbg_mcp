#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_dx_cbuffer_routes(c_http_router& router) {
    // POST /api/dx_cbuffer/slot
    router.post("/api/dx_cbuffer/slot", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"slot", 0},
            {"buffer_size", 256},
            {"buffer_data_hex", "0000803F0000000000000000000000000000803F000000000000000000000000"}
        });
    });

    // GET /api/dx_cbuffer/list
    router.get("/api/dx_cbuffer/list", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"bound_cbuffers_count", 2},
            {"slots", nlohmann::json::array({0, 1})}
        });
    });

    // POST /api/dx_cbuffer/matrices
    router.post("/api/dx_cbuffer/matrices", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"matrix_type", "4x4_FLOAT_ROW_MAJOR"},
            {"m00", 1.0}, {"m11", 1.0}, {"m22", 1.0}, {"m33", 1.0}
        });
    });
}

} // namespace handlers
