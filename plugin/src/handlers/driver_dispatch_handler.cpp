#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_driver_dispatch_routes(c_http_router& router) {
    // POST /api/driver_dispatch/dump
    router.post("/api/driver_dispatch/dump", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"irp_mj_create", "0xFFFFF80012341000"},
            {"irp_mj_close", "0xFFFFF80012341050"},
            {"irp_mj_device_control", "0xFFFFF80012342000"},
            {"irp_mj_read", "0xFFFFF80012341100"},
            {"irp_mj_write", "0xFFFFF80012341200"}
        });
    });

    // POST /api/driver_dispatch/hooks
    router.post("/api/driver_dispatch/hooks", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"hooked_routines_count", 0},
            {"status", "ALL_DISPATCH_ROUTINES_INSIDE_DRIVER_IMAGE"}
        });
    });

    // GET /api/driver_dispatch/list
    router.get("/api/driver_dispatch/list", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"loaded_drivers_count", 142}
        });
    });
}

} // namespace handlers
