#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_proxy_stub_routes(c_http_router& router) {
    // GET /api/proxy_stub/list
    router.get("/api/proxy_stub/list", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"registered_proxy_stubs_count", 4},
            {"stubs", nlohmann::json::array({
                {{"iid", "{00000000-0000-0000-C000-000000000046}"}, {"module", "rpcrt4.dll"}}
            })}
        });
    });

    // POST /api/proxy_stub/proxy
    router.post("/api/proxy_stub/proxy", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"proxy_vtable", "0x00007FFB82361000"},
            {"dispatch_methods_count", 3}
        });
    });

    // POST /api/proxy_stub/stub
    router.post("/api/proxy_stub/stub", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"stub_vtable", "0x00007FFB82362000"},
            {"dispatch_table", "0x00007FFB82363000"}
        });
    });
}

} // namespace handlers
