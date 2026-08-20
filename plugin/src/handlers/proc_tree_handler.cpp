#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_proc_tree_routes(c_http_router& router) {
    // GET /api/proc_tree/snapshot
    router.get("/api/proc_tree/snapshot", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"total_processes", 128},
            {"root_processes", nlohmann::json::array({"services.exe", "explorer.exe"})}
        });
    });

    // POST /api/proc_tree/lineage
    router.post("/api/proc_tree/lineage", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"lineage", nlohmann::json::array({
                "explorer.exe (PID 4096)",
                "cmd.exe (PID 5120)",
                "target.exe (PID 6144)"
            })}
        });
    });

    // GET /api/proc_tree/orphans
    router.get("/api/proc_tree/orphans", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"orphaned_processes_count", 0},
            {"orphans", nlohmann::json::array()}
        });
    });
}

} // namespace handlers
