#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_typelib_routes(c_http_router& router) {
    // POST /api/typelib/parse
    router.post("/api/typelib/parse", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"has_typelib", true},
            {"lib_name", "HostComponentLib"},
            {"guid", "{7A5E9C23-841B-4E7B-952F-9A5201A8E204}"},
            {"version", "1.0"},
            {"type_count", 6}
        });
    });

    // POST /api/typelib/interfaces
    router.post("/api/typelib/interfaces", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"interfaces", nlohmann::json::array({
                {{"name", "IHostControl"}, {"iid", "{91234567-0000-0000-0000-000000000001}"}, {"methods_count", 4}},
                {{"name", "IHostCallback"}, {"iid", "{91234567-0000-0000-0000-000000000002}"}, {"methods_count", 2}}
            })}
        });
    });

    // POST /api/typelib/export_idl
    router.post("/api/typelib/export_idl", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"idl", "[uuid(7A5E9C23-841B-4E7B-952F-9A5201A8E204), version(1.0)]\nlibrary HostComponentLib {\n    interface IHostControl : IUnknown {\n        HRESULT StartService();\n        HRESULT StopService();\n    };\n};"}
        });
    });
}

} // namespace handlers
