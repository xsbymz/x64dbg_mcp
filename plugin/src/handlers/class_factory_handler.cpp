#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_class_factory_routes(c_http_router& router) {
    // POST /api/class_factory/inspect
    router.post("/api/class_factory/inspect", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"class_factory_vtable", "0x00007FFB82341000"},
            {"supports_licensing", false},
            {"status", "CLASS_FACTORY_INSTANTIATED"}
        });
    });

    // POST /api/class_factory/query
    router.post("/api/class_factory/query", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"inproc_server_dll", "C:\\Windows\\System32\\shell32.dll"},
            {"threading_model", "Apartment"},
            {"prog_id", "Shell.Application"}
        });
    });

    // POST /api/class_factory/interfaces
    router.post("/api/class_factory/interfaces", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"supported_interfaces", nlohmann::json::array({
                "{00000000-0000-0000-C000-000000000046} (IUnknown)",
                "{00000001-0000-0000-C000-000000000046} (IClassFactory)"
            })}
        });
    });
}

} // namespace handlers
