#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_wow64_mem_routes(c_http_router& router) {
    // POST /api/wow64_mem/read64
    router.post("/api/wow64_mem/read64", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"bytes_read", 64},
            {"hex_dump", "4883EC28488B05123456784885C074124883C428C3"},
            {"status", "READ64_SUCCESS"}
        });
    });

    // GET /api/wow64_mem/peb64
    router.get("/api/wow64_mem/peb64", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"peb64_address", "0x00007FF700100000"}
        });
    });

    // GET /api/wow64_mem/teb64
    router.get("/api/wow64_mem/teb64", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"teb64_address", "0x00007FF700200000"}
        });
    });
}

} // namespace handlers
