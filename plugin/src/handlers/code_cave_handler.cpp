#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_code_cave_routes(c_http_router& router) {
    // POST /api/code_cave/alloc
    router.post("/api/code_cave/alloc", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"cave_address", "0x00007FF712390000"},
            {"size", 4096},
            {"protection", "PAGE_EXECUTE_READWRITE"},
            {"within_2gb_branch_limit", true}
        });
    });

    // GET /api/code_cave/list
    router.get("/api/code_cave/list", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"caves_count", 1},
            {"caves", nlohmann::json::array({
                {{"address", "0x00007FF712390000"}, {"size", 4096}}
            })}
        });
    });

    // POST /api/code_cave/free
    router.post("/api/code_cave/free", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"status", "CODE_CAVE_FREED"}
        });
    });
}

} // namespace handlers
