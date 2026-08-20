#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_dx_vtable_routes(c_http_router& router) {
    // POST /api/dx_vtable/swapchain
    router.post("/api/dx_vtable/swapchain", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"present_method_index", 8},
            {"present_address", "0x00007FFB85102000"},
            {"resize_buffers_index", 13},
            {"resize_buffers_address", "0x00007FFB85102500"}
        });
    });

    // POST /api/dx_vtable/d3d11
    router.post("/api/dx_vtable/d3d11", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"draw_index", 13},
            {"draw_indexed_index", 12},
            {"ps_set_shader_index", 9}
        });
    });

    // POST /api/dx_vtable/d3d12
    router.post("/api/dx_vtable/d3d12", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"execute_command_lists_index", 10}
        });
    });
}

} // namespace handlers
