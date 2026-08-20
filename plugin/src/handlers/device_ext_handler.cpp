#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_device_ext_routes(c_http_router& router) {
    // POST /api/device_ext/dump
    router.post("/api/device_ext/dump", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"device_extension_ptr", "0xFFFF800012350000"},
            {"device_extension_size", 256},
            {"status", "DEVICE_EXTENSION_DUMPED"}
        });
    });

    // POST /api/device_ext/stack
    router.post("/api/device_ext/stack", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"attached_devices_count", 1},
            {"device_stack", nlohmann::json::array({
                {{"device_object", "0xFFFF800012340000"}, {"driver_name", "\\Driver\\SampleDriver"}}
            })}
        });
    });

    // POST /api/device_ext/list
    router.post("/api/device_ext/list", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"devices_count", 1}
        });
    });
}

} // namespace handlers
