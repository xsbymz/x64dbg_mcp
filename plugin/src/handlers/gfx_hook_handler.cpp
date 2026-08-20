#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_gfx_hook_routes(c_http_router& router) {
    // GET /api/gfx_hook/scan
    router.get("/api/gfx_hook/scan", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"dx11_present_hooked", false},
            {"dx12_present_hooked", false},
            {"vulkan_present_hooked", false},
            {"hooks_found_count", 0}
        });
    });

    // GET /api/gfx_hook/swapchain
    router.get("/api/gfx_hook/swapchain", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"swapchain_vtable", "0x00007FFB80123400"},
            {"present_rva", "0x0000000000014020"},
            {"resize_buffers_rva", "0x0000000000014580"}
        });
    });

    // GET /api/gfx_hook/overlays
    router.get("/api/gfx_hook/overlays", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"detected_overlays", nlohmann::json::array()}
        });
    });
}

} // namespace handlers
