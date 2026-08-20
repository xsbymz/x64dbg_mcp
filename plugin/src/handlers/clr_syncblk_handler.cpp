#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_clr_syncblk_routes(c_http_router& router) {
    // GET /api/clr_syncblk/list
    router.get("/api/clr_syncblk/list", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"active_syncblocks_count", 2},
            {"syncblocks", nlohmann::json::array({
                {{"index", 1}, {"object_ptr", "0x0000021400501000"}, {"monitor_held", true}}
            })}
        });
    });

    // POST /api/clr_syncblk/inspect
    router.post("/api/clr_syncblk/inspect", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"has_syncblock", true},
            {"syncblock_index", 1},
            {"hash_code", "0x3F8A102B"},
            {"recursion_count", 1}
        });
    });

    // POST /api/clr_syncblk/owner
    router.post("/api/clr_syncblk/owner", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"owning_thread_id", 1024},
            {"owning_clr_thread_ptr", "0x00007FFB90558000"}
        });
    });
}

} // namespace handlers
