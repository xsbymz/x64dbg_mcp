#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_branch_island_routes(c_http_router& router) {
    // POST /api/branch_island/allocate
    router.post("/api/branch_island/allocate", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"island_address", "0x00007FF712500000"},
            {"island_id", "island_01"},
            {"trampoline_opcode", "jmp qword ptr [rip+0]"},
            {"status", "RELAY_ISLAND_ALLOCATED"}
        });
    });

    // GET /api/branch_island/list
    router.get("/api/branch_island/list", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"active_islands_count", 1},
            {"islands", nlohmann::json::array({
                {{"island_id", "island_01"}, {"address", "0x00007FF712500000"}}
            })}
        });
    });

    // POST /api/branch_island/free
    router.post("/api/branch_island/free", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"status", "ISLAND_FREED"}
        });
    });
}

} // namespace handlers
